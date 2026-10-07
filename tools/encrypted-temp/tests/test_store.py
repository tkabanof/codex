import errno
import os
import random
from concurrent.futures import ThreadPoolExecutor

import pytest
from codex_encrypted_temp.store import StorageFailure, Store


@pytest.fixture
def store(tmp_path):
    result = Store(tmp_path, max_file_size=4096, capacity=16384, max_nodes=100)
    yield result
    result.shutdown()


def test_names_and_contents_never_appear_in_backing_files(store):
    directory = store.create("\\private-directory", directory=True)
    node = store.create("\\private-directory\\секретный-отчёт.txt")
    content = b"unique-confidential-payload-0123456789"
    store.write(node, content, 0)
    assert store.read(node, 0, 4096) == content
    for path in store.directory.iterdir():
        assert len(path.stem) == 32
        assert path.suffix == ".bin"
        raw = path.read_bytes()
        for secret in (content, b"private-directory", "секретный-отчёт".encode()):
            assert secret not in raw
        assert "секретный" not in path.name
    assert store.lookup("\\PRIVATE-DIRECTORY\\СЕКРЕТНЫЙ-ОТЧЁТ.TXT") is node
    assert store.children(directory) == [node]


def test_random_access_matches_bytearray(store):
    node = store.create("\\file")
    expected = bytearray()
    rng = random.Random(12)
    for _ in range(100):
        if rng.randrange(3) == 0:
            size = rng.randrange(400)
            store.resize(node, size)
            expected = expected[:size] + bytes(max(0, size - len(expected)))
        else:
            offset = rng.randrange(400)
            data = rng.randbytes(rng.randrange(1, 60))
            store.write(node, data, offset)
            expected += bytes(max(0, offset + len(data) - len(expected)))
            expected[offset : offset + len(data)] = data
        assert store.read(node, 0, 4096) == expected
        assert node.size == len(expected)
        assert store.used == len(expected)


def test_append_constrained_and_truncate_zeroes(store):
    node = store.create("\\data")
    store.write(node, b"hello", 0)
    store.write(node, b" world", 999, append=True)
    assert store.write(node, b"abcdefghij", 9, constrained=True) == 2
    assert store.read(node, 0, 100) == b"hello worab"
    assert store.write(node, b"x", 100, constrained=True) == 0
    store.resize(node, 3)
    store.resize(node, 8)
    assert store.read(node, 0, 100) == b"hel" + bytes(5)
    store.resize(node, 100, allocation_only=True)
    assert node.size == 8
    store.resize(node, 2, allocation_only=True)
    assert store.read(node, 0, 100) == b"he"


def test_rename_directory_keeps_open_handles_and_case(store):
    directory = store.create("\\before", True)
    child = store.create("\\before\\name")
    store.write(child, b"original", 0)
    store.rename(directory, "\\after")
    assert store.lookup("\\after\\name") is child
    assert store.read(child, 0, 100) == b"original"
    with pytest.raises(FileNotFoundError):
        store.lookup("\\before\\name")
    store.rename(child, "\\after\\NAME")
    assert str(child.path) == "\\after\\NAME"
    store.write(child, b"!", 0, append=True)
    assert store.read(child, 0, 100) == b"original!"


def test_delete_and_replace_preserve_open_handles(store):
    old = store.create("\\target")
    store.write(old, b"old", 0)
    new = store.create("\\new")
    store.write(new, b"new", 0)
    store.rename(new, "\\target", replace=True)
    assert store.lookup("\\target") is new
    assert store.read(old, 0, 100) == b"old"
    store.write(old, b"!", 0, append=True)
    old_backing = store._object_path(old)
    store.close_handle(old)
    assert not old_backing.exists()
    assert store.used == 3
    store.delete(new)
    with pytest.raises(FileNotFoundError):
        store.open("\\target")
    assert store.read(new, 0, 100) == b"new"
    store.close_handle(new)
    assert store.used == 0


def test_directory_errors_do_not_mutate_namespace(store):
    directory = store.create("\\dir", True)
    child = store.create("\\dir\\child")
    with pytest.raises(OSError) as error:
        store.delete(directory)
    assert error.value.errno == errno.ENOTEMPTY
    with pytest.raises(PermissionError):
        store.rename(directory, "\\dir\\nested")
    with pytest.raises(PermissionError):
        store.delete(store.root)
    with pytest.raises(NotADirectoryError):
        store.create("\\dir\\child\\nested")
    with pytest.raises(IsADirectoryError):
        store.read(directory, 0, 1)
    with pytest.raises(FileExistsError):
        store.create("\\DIR\\CHILD")
    assert store.lookup(child.path) is child
    assert not store.failed


@pytest.mark.parametrize(
    "path",
    [
        "relative",
        "C:\\file",
        "\\..\\escape",
        "\\file:stream",
        "\\\\server\\share",
        "\\a\\.\\b",
        "\\bad\x00name",
    ],
)
def test_path_traversal_and_streams_rejected(store, path):
    with pytest.raises(ValueError):
        store.create(path)


@pytest.mark.parametrize("attack", ["flip", "truncate", "swap", "replay", "missing"])
def test_tampering_faults_store_without_plaintext_fallback(store, attack):
    first = store.create("\\first")
    second = store.create("\\second")
    store.write(first, b"original", 0)
    old = store._object_path(first).read_bytes()
    store.write(first, b"changed!", 0)
    path = store._object_path(first)
    raw = path.read_bytes()
    if attack == "flip":
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    elif attack == "truncate":
        path.write_bytes(raw[:12])
    elif attack == "swap":
        path.write_bytes(store._object_path(second).read_bytes())
    elif attack == "replay":
        path.write_bytes(old)
    else:
        path.unlink()
    with pytest.raises(StorageFailure):
        store.read(first, 0, 100)
    with pytest.raises(StorageFailure):
        store.create("\\fallback")


def test_failed_atomic_replace_keeps_only_ciphertext_and_faults(store, monkeypatch):
    node = store.create("\\atomic")
    store.write(node, b"previous", 0)
    before = store._object_path(node).read_bytes()

    def fail(source, target):
        assert b"new secret content" not in source.read_bytes()
        raise OSError(errno.ENOSPC, "Injected disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(StorageFailure):
        store.write(node, b"new secret content", 0)
    assert store._object_path(node).read_bytes() == before
    assert not list(store.directory.glob("*.part"))
    with pytest.raises(StorageFailure):
        store.read(node, 0, 100)


def test_quota_failure_preserves_previous_content(store):
    node = store.create("\\limited")
    store.write(node, b"safe", 0)
    with pytest.raises(OSError) as error:
        store.write(node, b"too large", 4096)
    assert error.value.errno == errno.ENOSPC
    assert store.read(node, 0, 100) == b"safe"
    assert not store.failed


def test_concurrent_appends_do_not_lose_writes(store):
    node = store.create("\\shared")

    def append(number):
        store.write(node, bytes([number]), 0, append=True)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(100)))
    assert sorted(store.read(node, 0, 4096)) == list(range(100))


def test_each_write_has_unique_nonce_and_each_mount_a_new_namespace(store):
    node = store.create("\\same")
    snapshots = []
    for _ in range(10):
        store.write(node, b"same content", 0)
        snapshots.append(store._object_path(node).read_bytes())
    assert len({record[8:20] for record in snapshots}) == 10
    old_directory = store.directory
    store.shutdown()
    with pytest.raises(StorageFailure):
        store.read(node, 0, 100)
    fresh = Store(old_directory.parent)
    try:
        assert fresh.directory != old_directory
        with pytest.raises(FileNotFoundError):
            fresh.lookup("\\same")
    finally:
        fresh.shutdown()

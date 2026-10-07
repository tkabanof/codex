"""Real driver tests, never replaced with mocks. Explicitly opt in on Windows."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not os.environ.get("CODEX_TEMP_TEST_DRIVE"),
    reason="Requires Windows, WinFsp and an unused CODEX_TEMP_TEST_DRIVE (e.g. T:)",
)


def test_real_mount(tmp_path):
    from codex_encrypted_temp.store import Store
    from codex_encrypted_temp.windows import mount

    drive = os.environ["CODEX_TEMP_TEST_DRIVE"]
    assert len(drive) == 2 and drive[1] == ":"
    root = Path(drive + "\\")
    assert not root.exists(), "Never mount over an existing drive"
    store = Store(tmp_path / "ciphertext")
    filesystem = mount(store, drive)
    try:
        folder = root / "private-folder"
        folder.mkdir()
        path = folder / "секрет.txt"
        path.write_bytes(b"confidential bytes")
        with path.open("r+b") as stream:
            stream.seek(4)
            stream.write(b"XYZ")
            stream.flush()
            os.fsync(stream.fileno())
        assert path.read_bytes() == b"confXYZntial bytes"
        path.rename(folder / "renamed.txt")
        assert [p.name for p in folder.iterdir()] == ["renamed.txt"]
        env = {**os.environ, "TEMP": str(folder), "TMP": str(folder)}
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import tempfile,pathlib; p=pathlib.Path(tempfile.gettempdir())/'child.tmp'; "
                    "p.write_bytes(b'child process secret'); assert p.read_bytes()==b'child process secret'"
                ),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert child.returncode == 0, child.stderr
        for encrypted in store.directory.iterdir():
            raw = encrypted.read_bytes()
            assert b"child process secret" not in raw
            assert b"renamed.txt" not in raw
        (folder / "child.tmp").unlink()
        (folder / "renamed.txt").unlink()
        folder.rmdir()
    finally:
        filesystem.stop()
        store.shutdown()
    assert not root.exists()


@pytest.mark.skipif(
    not os.environ.get("CODEX_TEMP_TEST_BINARY"),
    reason="Requires the packaged temp-vault.bin from build-temp-vault.ps1",
)
def test_packaged_service_image_name_and_mount(tmp_path):
    import ctypes
    from ctypes import wintypes

    binary = Path(os.environ["CODEX_TEMP_TEST_BINARY"]).resolve(strict=True)
    assert binary.name == "temp-vault.bin"
    assert not binary.with_suffix(".exe").exists()
    drive = os.environ["CODEX_TEMP_TEST_DRIVE"]
    assert len(drive) == 2 and drive[1] == ":"
    root = Path(drive + "\\")
    assert not root.exists(), "Never mount over an existing drive"
    backing = tmp_path / "ciphertext for packaged service"
    process = subprocess.Popen(
        [str(binary), "--backing", str(backing), "--drive", drive],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000, False, process.pid)
        assert handle, ctypes.WinError(ctypes.get_last_error())
        try:
            length = wintypes.DWORD(32768)
            image = ctypes.create_unicode_buffer(length.value)
            assert kernel.QueryFullProcessImageNameW(
                handle, 0, image, ctypes.byref(length)
            )
            assert Path(image.value).samefile(binary)
            assert Path(image.value).name == "temp-vault.bin"
        finally:
            kernel.CloseHandle(handle)
        deadline = time.monotonic() + 30
        while not root.exists():
            assert process.poll() is None, "Packaged service exited before mounting"
            assert time.monotonic() < deadline, "Packaged service mount timed out"
            time.sleep(0.1)
        file = root / "packaged-secret.txt"
        file.write_bytes(b"packaged-service-confidential-payload")
        assert file.read_bytes() == b"packaged-service-confidential-payload"
        for encrypted in backing.glob("session-*/*"):
            raw = encrypted.read_bytes()
            assert b"packaged-secret.txt" not in raw
            assert b"packaged-service-confidential-payload" not in raw
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
    deadline = time.monotonic() + 10
    while root.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not root.exists(), "Drive must disappear when its service exits"

"""Real driver tests, never replaced with mocks. Explicitly opt in on Windows."""

import os
import subprocess
import sys
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

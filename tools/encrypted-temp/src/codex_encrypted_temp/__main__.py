import argparse
import os
import re
import sys
import threading

from .store import StorageFailure, Store


def main():
    parser = argparse.ArgumentParser(
        prog="temp-vault", description="Mount an ephemeral encrypted temporary drive"
    )
    parser.add_argument(
        "--backing", required=True, help="Directory for ciphertext only"
    )
    parser.add_argument("--drive", required=True, help="Unused drive letter, e.g. T:")
    parser.add_argument("--max-file-mib", type=int, default=64)
    parser.add_argument("--capacity-mib", type=int, default=512)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error(
            "Mounting requires Windows and WinFsp; the storage tests are cross-platform"
        )
    if not re.fullmatch(r"[D-Zd-z]:", args.drive):
        parser.error("Use an unused drive letter D: through Z:")
    drive = args.drive.upper()
    if os.path.lexists(drive + "\\"):
        parser.error("The drive is already in use")
    if os.path.splitdrive(os.path.abspath(args.backing))[0].upper() == drive:
        parser.error("Backing storage must be outside the mounted drive")
    from .windows import mount

    store = Store(
        args.backing, args.max_file_mib * 1024**2, args.capacity_mib * 1024**2
    )
    filesystem = None
    try:
        filesystem = mount(store, drive)
        print(
            f"Mounted encrypted temporary drive {drive}; keep this process running.",
            flush=True,
        )
        print(
            "Temporary files cannot be recovered after this process ends. Ctrl+C unmounts.",
            flush=True,
        )
        while not threading.Event().wait(0.5):
            store.check()
    except KeyboardInterrupt:
        pass
    except StorageFailure:
        print(
            "Encrypted storage failed; unmounting without plaintext fallback.",
            file=sys.stderr,
        )
        return 1
    finally:
        try:
            if filesystem is not None:
                filesystem.stop()
        finally:
            store.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())

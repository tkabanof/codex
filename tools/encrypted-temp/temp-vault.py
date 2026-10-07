"""Frozen service entry point; packaged as temp-vault.bin on Windows."""

from codex_encrypted_temp.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())

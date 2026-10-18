#!/usr/bin/env python3
"""Create and display a one-time initial UI password during installation."""
import argparse
import os
from pathlib import Path
import secrets

from bt_signature_detector.web import _password_hash


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("password_file", type=Path)
    args = parser.parse_args()
    password = secrets.token_urlsafe(24)
    args.password_file.parent.mkdir(parents=True, exist_ok=True)
    args.password_file.write_text(_password_hash(password), encoding="ascii")
    os.chmod(args.password_file, 0o600)
    print("Save this initial UI password now; it is shown only once:")
    print(password)
    return 0


if __name__ == "__main__": raise SystemExit(main())

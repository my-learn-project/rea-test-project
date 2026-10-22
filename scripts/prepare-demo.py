"""Validate the PUBLIC demonstration identity and initialize an absent build trust anchor."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
ENVELOPE_FIELDS = {"version", "kdf", "memory_kib", "iterations", "parallelism", "cipher",
                   "salt", "nonce", "ciphertext"}


class DemoError(RuntimeError):
    """A fixed diagnostic that never includes key, passphrase, token or device values."""


def read_regular(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink():
        raise DemoError(label + " must not be a symbolic link.")
    try:
        with path.open("rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise DemoError(label + " must be a regular file.")
            raw = source.read(limit + 1)
    except OSError:
        raise DemoError(label + " is unavailable.") from None
    if len(raw) > limit:
        raise DemoError(label + " exceeds its size limit.")
    return raw


def read_public_key(path: Path) -> str:
    try:
        text = read_regular(path, 128, "Public key").decode("ascii").strip()
    except UnicodeError:
        raise DemoError("Public key must be lowercase hexadecimal ASCII.") from None
    if PUBLIC_KEY_PATTERN.fullmatch(text) is None:
        raise DemoError("Public key must contain exactly 64 lowercase hexadecimal characters.")
    return text


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DemoError("Encrypted demo key contains duplicate JSON fields.")
        result[key] = value
    return result


def validate_envelope(path: Path) -> None:
    try:
        envelope = json.loads(read_regular(path, 16384, "Encrypted demo key"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError):
        raise DemoError("Encrypted demo key is not valid JSON.") from None
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise DemoError("Encrypted demo key must contain only the encrypted envelope fields; plaintext key/password fields are forbidden.")
    expected = {"version": 1, "kdf": "argon2id-v19", "memory_kib": 65536,
                "iterations": 3, "parallelism": 1, "cipher": "chacha20poly1305"}
    for name, value in expected.items():
        if type(envelope[name]) is not type(value) or envelope[name] != value:
            raise DemoError("Encrypted demo key has unsupported algorithm parameters.")
    for name, size in (("salt", 16), ("nonce", 12), ("ciphertext", 48)):
        value = envelope[name]
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise DemoError("Encrypted demo key has invalid encoded fields.")
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        except ValueError:
            raise DemoError("Encrypted demo key has invalid encoded fields.") from None
        if len(decoded) != size or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
            raise DemoError("Encrypted demo key has invalid encoded field lengths.")


def load_demo_identity(root: Path) -> tuple[str, bytes, Path]:
    directory = root / "demo" / "keys"
    if directory.is_symlink():
        raise DemoError("Public demo key directory must not be a symbolic link.")
    public_key = read_public_key(directory / "demo.public.hex")
    private_key = directory / "demo.private.json"
    validate_envelope(private_key)
    password = read_regular(directory / "demo.passphrase.txt", 1026, "Public demo passphrase")
    if password.endswith(b"\n"):
        password = password[:-1]
        if password.endswith(b"\r"):
            password = password[:-1]
    try:
        text = password.decode("utf-8")
    except UnicodeError:
        raise DemoError("Public demo passphrase must be UTF-8.") from None
    if not 12 <= len(text) or len(password) > 1024 or any(unicodedata.category(char) == "Cc" for char in text):
        raise DemoError("Public demo passphrase must have at least 12 characters, at most 1024 UTF-8 bytes, and no control characters.")
    return public_key, password, private_key


def assert_demo_trust(root: Path, expected: str) -> None:
    if (root / "config").is_symlink():
        raise DemoError("Build configuration directory must not be a symbolic link.")
    key = root / "config" / "trusted-public-key.hex"
    if not key.exists() and not key.is_symlink():
        raise DemoError("Build trust anchor is missing. Run python scripts/prepare-demo.py first.")
    if read_public_key(key) != expected:
        raise DemoError("Existing build trust anchor uses a custom identity. It was not changed; custom identities may still be built manually. Demo issuance requires the public demo identity.")


def prepare_demo(root: Path) -> bool:
    public_key, _, _ = load_demo_identity(root)
    directory = root / "config"
    if directory.is_symlink():
        raise DemoError("Build configuration directory must not be a symbolic link.")
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / "trusted-public-key.hex"
    try:
        with key.open("x", encoding="ascii", newline="\n") as target:
            target.write(public_key + "\n")
        return True
    except FileExistsError:
        assert_demo_trust(root, public_key)
        return False


def main() -> int:
    try:
        created = prepare_demo(PROJECT_ROOT)
    except DemoError as error:
        print("prepare-demo: " + str(error), file=sys.stderr)
        return 1
    except OSError:
        print("prepare-demo: public demo preparation failed; no existing trust anchor was replaced.", file=sys.stderr)
        return 1
    print("Public demo build trust anchor initialized." if created else "Existing public demo build trust anchor retained.")
    print("This published identity is for testing; anyone can issue its demo cards.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

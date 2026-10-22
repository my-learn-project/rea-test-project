"""Issue a local test card with the repository's PUBLIC demo identity, without printing it."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid


PROJECT_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("cardguard_prepare_demo", Path(__file__).with_name("prepare-demo.py"))
_prepare = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_prepare)
DemoError = _prepare.DemoError
TOKEN_PATTERN = re.compile(r"L1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}")
DEVICE_PATTERN = re.compile(r"[0-9a-f]{64}")


def bounded_process(command: list[str], data: bytes, timeout: float = 30) -> bytes:
    """Limit both pipes while reading concurrently; never echo subprocess diagnostics."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("DYLD_") and key not in {"QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH",
                                                                 "QML_IMPORT_PATH", "QML2_IMPORT_PATH"}}
    options = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NO_WINDOW}
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, **options)
    except OSError:
        raise DemoError("Required executable could not be started.") from None
    events = queue.Queue()

    def read_pipe(name, stream):
        try:
            events.put((name, stream.read(65537), False))
        except OSError:
            events.put((name, b"", True))
        finally:
            stream.close()

    def write_input():
        failed = False
        try:
            process.stdin.write(data)
            process.stdin.close()
        except OSError:
            failed = True
        events.put(("stdin", b"", failed))

    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        threading.Thread(target=read_pipe, args=(name, stream), daemon=True).start()
    threading.Thread(target=write_input, daemon=True).start()
    deadline = time.monotonic() + timeout
    received = {}
    try:
        while len(received) < 3 or process.poll() is None:
            if time.monotonic() >= deadline:
                raise DemoError("Diagnostic/issuer process exceeded its timeout.")
            try:
                name, output, failed = events.get(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if failed or len(output) > 65536:
                raise DemoError("Diagnostic/issuer I/O failed or exceeded its 64 KiB limit.")
            received[name] = output
        if process.wait(timeout=1) != 0:
            raise DemoError("Diagnostic/issuer process failed; no card was saved.")
        return received["stdout"]
    finally:
        if process.poll() is None:
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def protocol(app: Path, message: dict) -> dict:
    data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > 16384:
        raise DemoError("Diagnostic request exceeds the 16 KiB limit.")
    raw = bounded_process([str(app), "--stdio"], data, timeout=15)
    if re.fullmatch(rb"[^\r\n]+\r?\n", raw) is None:
        raise DemoError("Diagnostic entry point did not return one JSON response line.")
    try:
        response = json.loads(raw, object_pairs_hook=_prepare.unique_object)
    except (UnicodeError, ValueError):
        raise DemoError("Diagnostic entry point returned invalid JSON.") from None
    if not isinstance(response, dict) or type(response.get("ok")) is not bool:
        raise DemoError("Diagnostic entry point returned an invalid response shape.")
    return response


def executable(path: Path, label: str) -> Path:
    path = path.expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise DemoError(label + " is missing or not executable. Build the application and run cargo build --locked --release -p license-issuer; no tools are installed automatically.")
    return path


def native_mac_target() -> tuple[str, str]:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64", "aarch64-apple-darwin"
    if machine in {"x86_64", "amd64"}:
        return "x86_64", "x86_64-apple-darwin"
    raise DemoError("Unsupported native macOS architecture; specify --app and --issuer explicitly.")


def find_issuer(root: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        return executable(explicit, "Issuer")
    name = "license-issuer.exe" if sys.platform == "win32" else "license-issuer"
    candidates = [root / "target" / "release" / name]
    if sys.platform == "darwin":
        _, target = native_mac_target()
        candidates.insert(0, root / "target" / target / "release" / name)
    for candidate in candidates:
        if candidate.is_file():
            return executable(candidate, "Issuer")
    raise DemoError("Demo issuer is missing. Run cargo build --locked --release -p license-issuer, optionally with the native --target; no tools are installed automatically.")


def find_app(root: Path, explicit: Path | None) -> Path:
    if explicit is None:
        if sys.platform == "win32":
            explicit = root / "dist" / "client" / "CardGuard.exe"
        elif sys.platform == "darwin":
            arch, _ = native_mac_target()
            manifest = root / "build" / ("macos-" + arch) / "artifact.json"
            try:
                info = json.loads(_prepare.read_regular(manifest, 16384, "macOS artifact metadata"))
            except (UnicodeError, ValueError):
                raise DemoError("macOS artifact metadata is invalid; pass --app explicitly.") from None
            if not isinstance(info, dict) or not isinstance(info.get("app"), str) or not Path(info["app"]).is_absolute():
                raise DemoError("macOS artifact metadata lacks an absolute app path; pass --app explicitly.")
            explicit = Path(info["app"])
        else:
            raise DemoError("Pass --device-id to issue without a supported Windows/macOS app.")
    if explicit.suffix.lower() == ".app":
        explicit = explicit / "Contents" / "MacOS" / "CardGuard"
    return executable(explicit, "Application")


def save_card(path: Path, token: str, root: Path) -> None:
    if path.is_symlink():
        raise DemoError("Card output must not replace a symbolic link.")
    resolved = path.expanduser().absolute()
    if resolved.resolve().is_relative_to((root / "demo" / "keys").resolve()) or resolved.resolve().is_relative_to((root / "config").resolve()):
        raise DemoError("Card output must not replace demonstration identity or build configuration files.")
    name = resolved.name.lower()
    if name.endswith((".private.json", ".dpapi")) or "passphrase" in name:
        raise DemoError("Card output must not replace private-key or passphrase files.")
    if resolved.exists():
        existing = _prepare.read_regular(resolved, 4100, "Existing card output")
        try:
            replaceable = TOKEN_PATTERN.fullmatch(existing.decode("ascii").strip()) is not None
        except UnicodeError:
            replaceable = False
        if not replaceable:
            raise DemoError("Existing output is not a demo card; refusing to overwrite it.")
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="ascii", newline="\n", dir=resolved.parent,
                                         prefix=".card-", delete=False) as target:
            temporary = Path(target.name)
            if os.name != "nt":
                os.fchmod(target.fileno(), 0o600)
            target.write(token + "\n")
            target.flush()
            os.fsync(target.fileno())
        if resolved.is_symlink():
            raise DemoError("Card output became a symbolic link; refusing replacement.")
        os.replace(temporary, resolved)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def issue_demo(args, root: Path) -> Path:
    public_key, password, private_key = _prepare.load_demo_identity(root)
    _prepare.assert_demo_trust(root, public_key)
    if not args.subject.strip() or len(args.subject.encode("utf-8")) > 120 or any(unicodedata.category(c) == "Cc" for c in args.subject):
        raise DemoError("Subject must be nonempty, at most 120 UTF-8 bytes, and contain no controls.")
    issuer = find_issuer(root, args.issuer)
    app = None
    device = args.device_id
    if device is None:
        app = find_app(root, args.app)
        response = protocol(app, {"op": "device"})
        result = response.get("result")
        if not response["ok"] or not isinstance(result, dict) or not isinstance(result.get("device_id"), str):
            raise DemoError("Application could not read its device identity.")
        device = result["device_id"]
    if DEVICE_PATTERN.fullmatch(device) is None:
        raise DemoError("Device identity must be exactly 64 lowercase hexadecimal characters.")
    command = [str(issuer), "issue", "--private-key", str(private_key), "--subject", args.subject,
               "--device-id", device, "--license-id", "DEMO-" + uuid.uuid4().hex,
               "--valid-hours", str(args.valid_hours), "--passphrase-stdin"]
    raw = bounded_process(command, password + b"\n")
    try:
        token = raw.decode("ascii").strip()
    except UnicodeError:
        raise DemoError("Demo issuer returned invalid card bytes.") from None
    if len(token) > 4096 or TOKEN_PATTERN.fullmatch(token) is None:
        raise DemoError("Demo issuer returned an invalid card format.")
    if app is not None and protocol(app, {"op": "verify", "token": token})["ok"] is not True:
        raise DemoError("Selected application rejected the new demo card. Rebuild it with the public demo trust anchor; no card was saved.")
    output = args.output if args.output is not None else root / ".local" / "demo-card.txt"
    save_card(output, token, root)
    return output.absolute()


def valid_hours(value: str) -> int:
    try:
        hours = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer between 1 and 8784") from None
    if not 1 <= hours <= 8784:
        raise argparse.ArgumentTypeError("must be between 1 and 8784")
    return hours


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", type=Path)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--app", type=Path, help="macOS .app directory or direct native executable")
    source.add_argument("--device-id", help="64 lowercase hexadecimal characters; skips the app entirely")
    parser.add_argument("--subject", default="Public demonstration license")
    parser.add_argument("--valid-hours", type=valid_hours, default=24)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        output = issue_demo(args, PROJECT_ROOT)
    except DemoError as error:
        print("issue-demo: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("issue-demo: local demo issuance failed; no sensitive values were logged.", file=sys.stderr)
        return 1
    print("Public demo card saved to: " + str(output))
    print("This published identity is for testing; anyone can issue its demo cards.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

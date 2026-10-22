"""Native macOS bundle/protocol/GUI checks; reports never contain license tokens or device IDs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid


MAX_TOKEN_BYTES = 4096
MAX_PROCESS_OUTPUT = 256 * 1024
DEVICE_PATTERN = re.compile(r"[0-9a-f]{64}")
TOKEN_PATTERN = re.compile(r"L1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}")


class CheckFailed(RuntimeError):
    """Only fixed, non-sensitive diagnostics may be included in the report."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailed(message)


def run_process(command: list[str], *, data: bytes = b"", timeout: int = 12,
                environment: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Use a private process group so a timed-out GUI cannot leave its verifier running."""
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, start_new_session=True)
    try:
        stdout, stderr = process.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)
        raise CheckFailed("process exceeded its timeout") from None
    require(len(stdout) <= MAX_PROCESS_OUTPUT and len(stderr) <= MAX_PROCESS_OUTPUT,
            "process output exceeded the test limit")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def read_token(path: Path) -> str:
    with path.open("rb") as source:
        raw = source.read(MAX_TOKEN_BYTES + 5)
    require(len(raw) <= MAX_TOKEN_BYTES + 4, "token file exceeds the size limit")
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeError:
        raise CheckFailed("token file is not UTF-8") from None
    require(0 < len(token.encode("utf-8")) <= MAX_TOKEN_BYTES, "token file has an invalid size")
    return token


def request(client: Path, message: str | dict) -> dict:
    text = message if isinstance(message, str) else json.dumps(message, separators=(",", ":"))
    result = run_process([str(client), "--stdio"], data=(text + "\n").encode("utf-8"))
    require(result.returncode == 0, "verifier did not exit normally")
    lines = result.stdout.splitlines()
    require(len(lines) == 1, "verifier must emit exactly one response")
    try:
        response = json.loads(lines[0])
    except (UnicodeError, ValueError):
        raise CheckFailed("verifier returned invalid JSON") from None
    require(isinstance(response, dict) and isinstance(response.get("ok"), bool),
            "verifier response has an invalid shape")
    return response


def expect_rejection(client: Path, message: str | dict, code: str) -> None:
    response = request(client, message)
    require(response["ok"] is False and isinstance(response.get("error"), dict)
            and response["error"].get("code") == code, "verifier did not reject the request as expected")


def validate_png(path: Path) -> None:
    require(path.is_file() and not path.is_symlink(), "GUI screenshot is missing")
    with path.open("rb") as image:
        header = image.read(24)
    require(len(header) == 24 and header[:8] == b"\x89PNG\r\n\x1a\n" and header[12:16] == b"IHDR",
            "GUI screenshot is not a PNG")
    width, height = struct.unpack(">II", header[16:24])
    require(width >= 400 and height >= 300, "GUI screenshot dimensions are unexpectedly small")


def inspect_bundle(app: Path) -> dict:
    require(app.name == "CardGuard.app" and app.is_dir(), "--app must point to CardGuard.app")
    forbidden_suffixes = {".exe", ".key", ".pem", ".pfx", ".p12", ".dpapi", ".pdb"}
    for path in app.rglob("*"):
        relative = path.relative_to(app)
        name = path.name.lower()
        require(not any(word in name for word in ("issuer", "private", "passphrase", "credential", "demo-card"))
                and path.suffix.lower() not in forbidden_suffixes
                and name != "trusted-public-key.hex"
                and not any(part in {".git", ".local", ".cargo"} for part in relative.parts),
                "bundle contains a forbidden development, Windows or signing file")
        if path.is_symlink():
            require(path.resolve().is_relative_to(app), "bundle contains a link outside the application")
    hashes = {}
    for name in ("CardGuard", "license-client"):
        binary = app / "Contents" / "MacOS" / name
        require(binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK),
                "required native executable is missing or not executable")
        contents = binary.read_bytes()
        require(contents[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe",
                                 b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"},
                "required executable is not a native Mach-O binary")
        lowered = contents.lower()
        for windows_name in ("license-client.exe", "cardguard.exe"):
            require(windows_name.encode("ascii") not in lowered
                    and windows_name.encode("utf-16-le") not in lowered,
                    "native binary contains a hardcoded Windows executable name")
        hashes[name] = hashlib.sha256(contents).hexdigest()
    return {"binary_sha256": hashes}


class Suite:
    def __init__(self, report: Path):
        self.report = report
        self.tests: list[dict] = []

    def check(self, name: str, operation):
        start = time.monotonic()
        item = {"name": name, "status": "passed"}
        try:
            detail = operation()
            if isinstance(detail, dict):
                item.update(detail)
        except CheckFailed as error:
            item.update(status="failed", detail=str(error))
        except Exception:
            # Never serialize arbitrary exceptions: they may contain command/input data.
            item.update(status="failed", detail="test operation failed; inspect the local runtime environment")
        item["duration_seconds"] = round(time.monotonic() - start, 3)
        self.tests.append(item)
        print(f"{item['status'].upper()}: {name}", flush=True)
        return item["status"] == "passed"

    def screenshot(self, gui: Path, label: str, expected: int, token_file: Path | None = None) -> dict:
        screenshot = self.report.with_name(f"{self.report.stem}-{label}-{uuid.uuid4().hex[:8]}.png")
        require(not screenshot.exists() and not screenshot.is_symlink(), "screenshot output already exists")
        command = [str(gui), "--smoke-test", "--screenshot", str(screenshot)]
        if token_file is not None:
            command += ["--smoke-token-file", str(token_file)]
        environment = dict(os.environ, QT_QPA_PLATFORM="cocoa")
        for variable in list(environment):
            if variable.startswith("DYLD_") or variable in {
                "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML_IMPORT_PATH", "QML2_IMPORT_PATH"
            }:
                environment.pop(variable)
        result = run_process(command, timeout=25, environment=environment)
        require(result.returncode == expected, "native Qt smoke test returned an unexpected exit code")
        validate_png(screenshot)
        return {"exit_code": result.returncode, "screenshot": screenshot.name, "qt_platform": "cocoa"}


def write_token(directory: Path, label: str, token: str) -> Path:
    path = directory / f"{label}.txt"
    with path.open("x", encoding="utf-8") as target:
        os.chmod(path, 0o600)
        target.write(token)
    return path


def sign_for_device(issuer: Path, key: Path, password: bytearray, device: str) -> str:
    command = [str(issuer), "issue", "--private-key", str(key), "--subject", "macOS CI runtime test",
               "--device-id", device, "--license-id", str(uuid.uuid4()), "--valid-hours", "1", "--passphrase-stdin"]
    result = run_process(command, data=bytes(password) + b"\n", timeout=25)
    require(result.returncode == 0, "test issuer did not produce an authorization")
    try:
        token = result.stdout.decode("ascii").strip()
    except UnicodeError:
        raise CheckFailed("test issuer returned invalid token bytes") from None
    require(len(token) <= MAX_TOKEN_BYTES and TOKEN_PATTERN.fullmatch(token) is not None,
            "test issuer returned an invalid token format")
    return token


def test_signed_token(suite: Suite, client: Path, gui: Path, temporary: Path, token: str, label: str) -> None:
    require(TOKEN_PATTERN.fullmatch(token) is not None, "provided token has an invalid format")
    valid_path = write_token(temporary, label + "-valid", token)
    parts = token.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    tampered = ".".join(parts)
    tampered_path = write_token(temporary, label + "-tampered", tampered)

    def valid_backend():
        response = request(client, {"op": "verify", "token": token})
        require(response["ok"] is True, "authentic authorization was rejected")

    suite.check(label + "-authentic-backend", valid_backend)
    suite.check(label + "-tampered-signature-backend",
                lambda: expect_rejection(client, {"op": "verify", "token": tampered}, "invalid_signature"))
    suite.check(label + "-authentic-native-gui", lambda: suite.screenshot(gui, label + "-valid", 0, valid_path))
    suite.check(label + "-tampered-native-gui", lambda: suite.screenshot(gui, label + "-tampered", 2, tampered_path))
    suite.check(label + "-diagnostic-helper-independence",
                lambda: test_helper_independence(suite, gui, temporary, valid_path, tampered_path, label))


def sign_test_bundle(app: Path) -> None:
    """Ad-hoc sign the disposable mutated bundle, leaving the formal bundle untouched."""
    result = run_process(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--timestamp=none",
                          "--options", "0", str(app)], timeout=60)
    require(result.returncode == 0, "could not ad-hoc sign the disposable helper test bundle")
    result = run_process(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=30)
    require(result.returncode == 0, "disposable helper test bundle signature verification failed")


def test_helper_independence(suite: Suite, gui: Path, temporary: Path,
                             valid_path: Path, tampered_path: Path, label: str) -> dict:
    """Exercise real GUI outcomes with absent and executable forged diagnostic helpers."""
    original_app = gui.parents[2]
    fixture_root = temporary / (label + "-helper-boundary")
    fixture_root.mkdir(mode=0o700)
    # macOS /var aliases /private/var; compare canonical paths on both sides.
    fixture_root = fixture_root.resolve()
    copied_app = fixture_root / "CardGuard.app"
    shutil.copytree(original_app, copied_app, symlinks=True)
    for path in copied_app.rglob("*"):
        if path.is_symlink():
            require(path.resolve().is_relative_to(copied_app),
                    "copied test bundle contains a link outside its own application")
    copied_gui = copied_app / "Contents" / "MacOS" / "CardGuard"
    copied_helper = copied_gui.with_name("license-client")
    require(copied_helper.is_file() and not copied_helper.is_symlink(), "copied diagnostic helper is invalid")
    copied_helper.unlink()
    sign_test_bundle(copied_app)
    missing_valid = suite.screenshot(copied_gui, label + "-helper-missing-valid", 0, valid_path)
    missing_tampered = suite.screenshot(copied_gui, label + "-helper-missing-tampered", 2, tampered_path)

    marker = fixture_root / "helper-invoked.marker"
    forged_result = {"ok": True, "result": {
        "device_id": "1" * 64, "license_id": "FORGED-TEST-FIXTURE", "subject": "Forged helper test fixture",
        "issued_at": 1, "expires_at": 4102444800, "product": "card-demo", "version": 1}}
    script = ("#!/bin/sh\numask 077\n: > " + shlex.quote(str(marker)) + "\n"
              "while IFS= read -r request; do\n  printf '%s\\n' "
              + shlex.quote(json.dumps(forged_result, separators=(",", ":"))) + "\ndone\n")
    with copied_helper.open("x", encoding="utf-8") as target:
        target.write(script)
    copied_helper.chmod(0o700)
    sign_test_bundle(copied_app)
    # Verify that this is an executable, working forgery; a broken stub would prove nothing.
    control = request(copied_helper, {"op": "verify", "token": "fixture-probe"})
    require(control["ok"] is True and marker.is_file(), "forged helper control did not return success and record invocation")
    marker.unlink()
    forged_tampered = suite.screenshot(copied_gui, label + "-helper-forged-tampered", 2, tampered_path)
    require(not marker.exists(), "GUI invoked the forged diagnostic helper")
    return {"missing_helper_authentic": missing_valid, "missing_helper_tampered": missing_tampered,
            "forged_helper_tampered": forged_tampered, "forged_helper_control_passed": True,
            "forged_helper_invoked_by_gui": False, "test_bundle_signing": "ad-hoc-disposable-copy"}


def run_suite(args, suite: Suite) -> None:
    app = args.app.resolve()
    require(not args.app.is_symlink(), "application path must not be a symbolic link")
    if not suite.check("bundle-content-and-native-binaries", lambda: inspect_bundle(app)):
        return
    client = app / "Contents" / "MacOS" / "license-client"
    gui = app / "Contents" / "MacOS" / "CardGuard"
    devices: list[str] = []

    def stable_device():
        for _ in range(2):
            response = request(client, {"op": "device"})
            require(response["ok"] is True and isinstance(response.get("result"), dict), "device read failed")
            device = response["result"].get("device_id")
            require(isinstance(device, str) and DEVICE_PATTERN.fullmatch(device) is not None,
                    "device identifier has an invalid format")
            devices.append(device)
        require(devices[0] == devices[1], "device identifier was not stable across verifier processes")
        gui_response = request(gui, {"op": "device"})
        require(gui_response["ok"] is True and isinstance(gui_response.get("result"), dict)
                and gui_response["result"].get("device_id") == devices[0],
                "application diagnostic entry point did not match the standalone device identity")

    has_device = suite.check("device-format-and-stability", stable_device)
    for label, message in (
        ("invalid-json", "{"),
        ("unknown-operation", {"op": "unknown"}),
        ("external-device-rejected", {"op": "verify", "token": "x", "device_id": "0" * 64}),
        ("external-time-rejected", {"op": "verify", "token": "x", "now": 1}),
        ("external-public-key-rejected", {"op": "verify", "token": "x", "public_key": "0" * 64}),
    ):
        suite.check(label, lambda message=message: expect_rejection(client, message, "invalid_request"))
    if has_device:
        for label, token in (("empty-token", ""), ("malformed-token", "not-a-card"), ("oversized-token", "x" * 5000)):
            suite.check(label, lambda token=token: expect_rejection(client, {"op": "verify", "token": token}, "invalid_token"))
    suite.check("device-native-gui", lambda: suite.screenshot(gui, "device", 0))
    with tempfile.TemporaryDirectory(prefix="cardguard-runtime-") as temporary_name:
        temporary = Path(temporary_name)
        invalid_path = write_token(temporary, "invalid", "not-a-card")
        suite.check("malformed-native-gui", lambda: suite.screenshot(gui, "invalid", 2, invalid_path))
        if args.token_file:
            suite.check("provided-license-workflow",
                        lambda: test_signed_token(suite, client, gui, temporary, read_token(args.token_file), "provided"))
        if args.issuer and has_device:
            password = bytearray()
            try:
                with args.passphrase_file.open("rb") as source:
                    password.extend(source.read(1027))
                if password.endswith(b"\n"):
                    password.pop()
                    if password.endswith(b"\r"):
                        password.pop()
                require(12 <= len(password) <= 1024, "test passphrase file has an invalid size")
                issuer = args.issuer.resolve()
                key = args.private_key.resolve()
                require(not issuer.is_relative_to(app) and not key.is_relative_to(app)
                        and not args.passphrase_file.resolve().is_relative_to(app),
                        "test signing material must remain outside the application bundle")
                token = sign_for_device(issuer, key, password, devices[0])
                test_signed_token(suite, client, gui, temporary, token, "issued")
                other_device = ("1" if devices[0] == "0" * 64 else "0") * 64
                wrong = sign_for_device(issuer, key, password, other_device)
                wrong_path = write_token(temporary, "wrong-device", wrong)
                suite.check("wrong-device-backend",
                            lambda: expect_rejection(client, {"op": "verify", "token": wrong}, "wrong_device"))
                suite.check("wrong-device-native-gui", lambda: suite.screenshot(gui, "wrong-device", 2, wrong_path))
            finally:
                password[:] = b"\0" * len(password)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--issuer", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--passphrase-file", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("native macOS tests require macOS and the Cocoa desktop session; this host is not macOS")
    signing_options = (args.issuer, args.private_key, args.passphrase_file)
    if any(signing_options) and not all(signing_options):
        parser.error("--issuer, --private-key and --passphrase-file must be supplied together")
    if args.report.suffix.lower() != ".json" or args.report.is_symlink():
        parser.error("--report must be a regular .json output path")
    report = args.report.resolve()
    if report.is_relative_to(args.app.resolve()):
        parser.error("runtime reports and screenshots must be outside the application bundle")
    report.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    suite = Suite(report)
    suite.check("runtime-suite", lambda: run_suite(args, suite))
    data = {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "platform": "macOS",
            "architecture": platform.machine(), "qt_platform": "cocoa",
            "signed_license_tests": "requested" if args.token_file or args.issuer else "not-requested",
            "success": all(item["status"] == "passed" for item in suite.tests), "tests": suite.tests}
    temporary_report = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=report.parent, suffix=".json", delete=False) as output:
            temporary_report = Path(output.name)
            json.dump(data, output, indent=2, ensure_ascii=False)
            output.write("\n")
        os.replace(temporary_report, report)
    finally:
        if temporary_report is not None and temporary_report.exists():
            temporary_report.unlink()
    print("Runtime report written; sensitive token/device values were omitted.")
    return 0 if data["success"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, CheckFailed):
        print("test-macos: runtime setup or report writing failed; no sensitive values were logged", file=sys.stderr)
        raise SystemExit(1)

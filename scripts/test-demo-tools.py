"""Offline stdlib tests using temporary fake identities; no real keys/apps or issuance."""
from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load_script("prepare-demo")
issue = load_script("issue-demo")
TOKEN = "L1.e30." + "A" * 86  # Format fixture only; this is not a valid signed authorization.


class DemoToolTests(unittest.TestCase):
    def setUp(self):
        build = PROJECT_ROOT / "build"
        build.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="demo-tools-test-", dir=build)
        self.root = Path(self.temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to(build.resolve()))
        self.addCleanup(self.temporary.cleanup)
        self.keys = self.root / "demo" / "keys"
        self.keys.mkdir(parents=True)
        self.public = "1" * 64
        self.password = b"public-fixture-passphrase"
        (self.keys / "demo.public.hex").write_text(self.public + "\n", encoding="ascii")
        (self.keys / "demo.passphrase.txt").write_bytes(self.password + b"\r\n")
        self.envelope = {"version": 1, "kdf": "argon2id-v19", "memory_kib": 65536,
                         "iterations": 3, "parallelism": 1, "cipher": "chacha20poly1305"}
        for name, size in (("salt", 16), ("nonce", 12), ("ciphertext", 48)):
            self.envelope[name] = base64.urlsafe_b64encode(bytes(size)).decode().rstrip("=")
        self.private = self.keys / "demo.private.json"
        self.private.write_text(json.dumps(self.envelope), encoding="utf-8")
        self.output = self.root / "cards" / "card.txt"

    def args(self, **changes):
        options = dict(issuer=None, app=None, device_id="f" * 64, subject="Fixture user",
                       valid_hours=24, output=self.output)
        options.update(changes)
        return SimpleNamespace(**options)

    def test_prepare_initializes_missing_trust_and_preserves_identical_file(self):
        self.assertTrue(prepare.prepare_demo(self.root))
        trusted = self.root / "config" / "trusted-public-key.hex"
        before = trusted.stat().st_mtime_ns
        self.assertFalse(prepare.prepare_demo(self.root))
        self.assertEqual(trusted.read_text().strip(), self.public)
        self.assertEqual(trusted.stat().st_mtime_ns, before)
        self.assertFalse((self.root / ".local").exists())

    def test_prepare_refuses_custom_trust_without_replacing_it(self):
        trusted = self.root / "config" / "trusted-public-key.hex"
        trusted.parent.mkdir()
        trusted.write_text("2" * 64 + "\n", encoding="ascii")
        with self.assertRaisesRegex(prepare.DemoError, "custom identity"):
            prepare.prepare_demo(self.root)
        self.assertEqual(trusted.read_text(), "2" * 64 + "\n")

    def test_public_identity_rejects_plaintext_duplicate_and_bad_parameters(self):
        bad_envelopes = [dict(self.envelope, seed="plaintext-not-allowed"),
                         dict(self.envelope, memory_kib=2 ** 32),
                         dict(self.envelope, version=True),
                         dict(self.envelope, ciphertext="A" * 63)]
        for envelope in bad_envelopes:
            with self.subTest(envelope_fields=list(envelope)):
                self.private.write_text(json.dumps(envelope), encoding="utf-8")
                with self.assertRaises(prepare.DemoError):
                    prepare.load_demo_identity(self.root)
        self.private.write_text(json.dumps(self.envelope).replace('"version": 1', '"version": 1, "version": 1'), encoding="utf-8")
        with self.assertRaises(prepare.DemoError):
            prepare.load_demo_identity(self.root)

    def test_public_identity_rejects_invalid_password_and_public_key(self):
        password_file = self.keys / "demo.passphrase.txt"
        for password in (b"short", b"x" * 1025, b"long-enough\x00password", b"long-enough\npassword"):
            password_file.write_bytes(password)
            with self.assertRaises(prepare.DemoError):
                prepare.load_demo_identity(self.root)
        password_file.write_bytes(self.password + b"\n")
        (self.keys / "demo.public.hex").write_text("not-a-public-key", encoding="ascii")
        with self.assertRaises(prepare.DemoError):
            prepare.load_demo_identity(self.root)

    def test_issue_refuses_identity_mismatch_before_any_process(self):
        prepare.prepare_demo(self.root)
        (self.root / "config" / "trusted-public-key.hex").write_text("2" * 64)
        with mock.patch.object(issue, "bounded_process") as process:
            with self.assertRaisesRegex(issue.DemoError, "custom identity"):
                issue.issue_demo(self.args(), self.root)
            process.assert_not_called()

    def test_explicit_device_skips_app_and_password_only_goes_to_stdin(self):
        prepare.prepare_demo(self.root)
        with mock.patch.object(issue, "find_issuer", return_value=self.root / "fake-issuer"), \
                mock.patch.object(issue, "find_app") as app, \
                mock.patch.object(issue, "bounded_process", return_value=(TOKEN + "\n").encode()) as process:
            issue.issue_demo(self.args(), self.root)
            app.assert_not_called()
            command, stdin = process.call_args.args
            self.assertEqual(stdin, self.password + b"\n")
            self.assertNotIn(self.password.decode(), command)
            self.assertIn("--passphrase-stdin", command)
        self.assertEqual(self.output.read_text().strip(), TOKEN)

    def test_app_mode_verifies_before_saving_and_rejects_old_build_identity(self):
        prepare.prepare_demo(self.root)
        with mock.patch.object(issue, "find_issuer", return_value=self.root / "fake-issuer"), \
                mock.patch.object(issue, "find_app", return_value=self.root / "fake-app"), \
                mock.patch.object(issue, "bounded_process", return_value=(TOKEN + "\n").encode()), \
                mock.patch.object(issue, "protocol", side_effect=[
                    {"ok": True, "result": {"device_id": "f" * 64}}, {"ok": False}]) as protocol:
            with self.assertRaisesRegex(issue.DemoError, "Rebuild"):
                issue.issue_demo(self.args(device_id=None), self.root)
            self.assertEqual(protocol.call_count, 2)
        self.assertFalse(self.output.exists())

    def test_output_rejects_noncard_private_and_dpapi_without_changes(self):
        for name, content in (("existing.txt", b"not a card"),
                              ("demo.private.json", (TOKEN + "\n").encode()),
                              ("demo-passphrase.dpapi", b"protected fixture data")):
            output = self.root / name
            output.write_bytes(content)
            with self.assertRaises(issue.DemoError):
                issue.save_card(output, TOKEN, self.root)
            self.assertEqual(output.read_bytes(), content)

    def test_output_can_replace_only_an_existing_card(self):
        issue.save_card(self.output, TOKEN, self.root)
        replacement = TOKEN[:-1] + "B"
        issue.save_card(self.output, replacement, self.root)
        self.assertEqual(self.output.read_text().strip(), replacement)

    @unittest.skipIf(os.name == "nt", "POSIX permission and symbolic-link behavior")
    def test_existing_output_directory_permissions_are_preserved(self):
        self.output.parent.mkdir(mode=0o755)
        self.output.parent.chmod(0o755)
        issue.save_card(self.output, TOKEN, self.root)
        self.assertEqual(stat.S_IMODE(self.output.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX permission and symbolic-link behavior")
    def test_new_output_directory_private_file_and_no_symlink_overwrite(self):
        issue.save_card(self.output, TOKEN, self.root)
        self.assertEqual(stat.S_IMODE(self.output.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        link = self.output.with_name("link.txt")
        link.symlink_to(self.output)
        with self.assertRaises(issue.DemoError):
            issue.save_card(link, TOKEN[:-1] + "B", self.root)
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.output.read_text().strip(), TOKEN)

    def test_macos_native_issuer_preferred_and_app_manifest_resolved(self):
        native = self.root / "target" / "aarch64-apple-darwin" / "release" / "license-issuer"
        native.parent.mkdir(parents=True)
        native.write_bytes(b"fixture")
        app = self.root / "dist" / "CardGuard.app"
        manifest = self.root / "build" / "macos-arm64" / "artifact.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"app": str(app), "archive": "unused.zip"}))
        with mock.patch.object(issue.sys, "platform", "darwin"), \
                mock.patch.object(issue.platform, "machine", return_value="arm64"), \
                mock.patch.object(issue, "executable", side_effect=lambda path, label: path):
            self.assertEqual(issue.find_issuer(self.root, None), native)
            self.assertEqual(issue.find_app(self.root, None), app / "Contents" / "MacOS" / "CardGuard")

    def test_cli_does_not_print_card_password_or_device(self):
        prepare.prepare_demo(self.root)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issue, "PROJECT_ROOT", self.root), \
                mock.patch.object(issue.sys, "argv", ["issue-demo.py", "--device-id", "f" * 64, "--output", str(self.output)]), \
                mock.patch.object(issue, "find_issuer", return_value=self.root / "fake-issuer"), \
                mock.patch.object(issue, "bounded_process", return_value=(TOKEN + "\n").encode()), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(issue.main(), 0)
        for secret in (TOKEN, self.password.decode(), "f" * 64):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

    def test_process_limits_success_oversized_output_and_timeout(self):
        self.assertEqual(issue.bounded_process([sys.executable, "-c", "print('fixture')"], b""), b"fixture\r\n" if os.name == "nt" else b"fixture\n")
        for code, timeout in (("import sys;sys.stdout.buffer.write(b'x'*70000)", 5),
                              ("import time;time.sleep(5)", 0.1)):
            with self.assertRaises(issue.DemoError):
                issue.bounded_process([sys.executable, "-c", code], b"", timeout=timeout)


if __name__ == "__main__":
    unittest.main()

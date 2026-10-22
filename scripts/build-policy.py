"""Build the selected authorization policy with pinned xollvm; fail if virtualization disappears."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "windows-x64": "x86_64-pc-windows-msvc",
    "macos-arm64": "arm64-apple-macosx13.0.0",
    "macos-x86_64": "x86_64-apple-macosx13.0.0",
}


def run(arguments: list[str]) -> str:
    result = subprocess.run(arguments, cwd=ROOT, text=True, capture_output=True, timeout=180)
    if result.returncode:
        print(result.stdout[-6000:], file=sys.stderr)
        print(result.stderr[-6000:], file=sys.stderr)
        raise RuntimeError(f"Policy compilation failed: {Path(arguments[0]).name}")
    return result.stdout


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digest() -> str:
    # Git normalizes line endings; Windows and macOS must compute the same value.
    value = hashlib.sha256()
    for name in ("authorization_policy.h", "authorization_policy.cpp"):
        value.update(name.encode() + b"\0")
        value.update((ROOT / "frontend" / name).read_bytes().replace(b"\r\n", b"\n"))
    return value.hexdigest()


def checked_output(path: Path) -> Path:
    # Check the lexical path before resolve(), which would hide a symlink or
    # Windows junction. Only this project's build tree is writable here.
    absolute = Path(os.path.abspath(path))
    build = ROOT / "build"
    if absolute == build or not absolute.is_relative_to(build):
        raise RuntimeError("Policy output must be inside this project's build directory.")
    cursor = absolute
    while cursor != ROOT:
        if cursor.is_symlink() or getattr(cursor, "is_junction", lambda: False)():
            raise RuntimeError("Policy output must not contain symlinks or junctions.")
        cursor = cursor.parent
    return absolute.resolve()


def artifact_path(directory: Path, name: str) -> Path:
    path = directory / name
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise RuntimeError("Policy artifact must not be a symlink or junction.")
    return path


def verify_vm_report(details: dict, target: str) -> None:
    if not isinstance(details, dict) or details.get("schema") != "llvm_obfuscator.obf_map" or details.get("schema_version") != 1:
        raise RuntimeError("Unrecognized xollvm transformation report.")
    module = details.get("module", {})
    triple = module.get("target_triple", "") if isinstance(module, dict) else ""
    expected = TARGETS[target]
    # Windows clang appends its compatible MSVC version to the target triple.
    target_matches = isinstance(triple, str) and (triple.startswith(expected) if target == "windows-x64" else triple == expected)
    functions = details.get("functions", [])
    covered = isinstance(functions, list) and any(
        isinstance(function, dict) and function.get("name") == "cardguard_policy_allows"
        and function.get("skipped") is False and function.get("declaration") is False
        and isinstance(function.get("passes"), list) and any(
            isinstance(item, dict) and item.get("id") == "vm" and item.get("status") == "ran"
            and item.get("changed") is True for item in function["passes"])
        for function in functions)
    if not target_matches or not covered:
        raise RuntimeError("xollvm did not report a successful policy VM transform for this target.")


def verify_object_target(path: Path, target: str) -> None:
    header = path.read_bytes()[:20]
    if target == "windows-x64":
        matches = len(header) >= 20 and header[:2] == b"\x64\x86"
    else:
        expected_cpu = 0x0100000C if target == "macos-arm64" else 0x01000007
        matches = (len(header) >= 20 and header[:4] == b"\xcf\xfa\xed\xfe"
                   and struct.unpack_from("<I", header, 4)[0] == expected_cpu)
    if not matches:
        raise RuntimeError("Policy object is not a native object for the requested target.")


def verify_artifact(directory: Path, target: str) -> dict:
    report = json.loads(artifact_path(directory, "protection.json").read_text())
    if not isinstance(report, dict):
        raise RuntimeError("Policy protection report must be a JSON object.")
    object_file = artifact_path(directory, "authorization_policy.obj" if target == "windows-x64" else "authorization_policy.o")
    xollvm_report = artifact_path(directory, "xollvm-report.json")
    if not (report["target"] == target and report["source_sha256"] == source_digest()
            and report["object_sha256"] == digest(object_file)
            and report["virtualization_survives_optimization"] is True
            and report["xollvm_version"] == "0.11.1"
            and report["mode"] == "clang-integrated"
            and report["scope"] == ["cardguard_policy_allows"]
            and report["cfg_metadata"] is (target == "windows-x64")
            and report["xollvm_report_sha256"] == digest(xollvm_report)):
        raise RuntimeError("Policy object/report does not match this source and target.")
    verify_object_target(object_file, target)
    verify_vm_report(json.loads(xollvm_report.read_text()), target)
    # CI transfers only the object and both reports. When IR is present locally,
    # also ensure that its recorded evidence was not replaced after generation.
    optimized = artifact_path(directory, "policy.optimized.ll")
    if optimized.exists():
        ir = optimized.read_text()
        if report["optimized_ir_sha256"] != digest(optimized) or "vm.bytecode" not in ir or "__vm_engine" not in ir:
            raise RuntimeError("Optimized policy IR does not match its virtualization evidence.")
        if target == "windows-x64" and '"cfguard"' not in ir:
            raise RuntimeError("Control Flow Guard metadata was lost during virtualization.")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--clang", type=Path)
    parser.add_argument("--opt", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--seed", type=int, default=20261022)
    args = parser.parse_args()
    output = checked_output(args.output)
    if args.verify_only:
        verify_artifact(output, args.target)
        print(f"Verified protected policy: {args.target}")
        return
    if not args.clang:
        raise RuntimeError("Provide --clang from the pinned xollvm installation.")
    clang = str(args.clang.resolve())
    version = run([clang, "--version"]).splitlines()[0]
    if not re.search(r"version 22\.", version):
        raise RuntimeError("This build requires the pinned LLVM 22 toolchain.")
    output.mkdir(parents=True, exist_ok=True)
    windows = args.target == "windows-x64"
    resource = run([clang, "-print-resource-dir"]).strip()
    flags = [f"--target={TARGETS[args.target]}", "-ffreestanding", "-nostdinc",
             "-isystem", str(Path(resource) / "include"), "-fno-exceptions", "-fno-rtti"]
    if windows:
        flags += ["-Xclang", "-cfguard", "-fms-runtime-lib=dll"]
    else:
        flags += ["-fPIC", "-fstack-protector-strong"]
    transformed, optimized = (artifact_path(output, name) for name in ("policy.obf.ll", "policy.optimized.ll"))
    object_file = artifact_path(output, "authorization_policy.obj" if windows else "authorization_policy.o")
    xollvm_report = artifact_path(output, "xollvm-report.json")
    protection_report = artifact_path(output, "protection.json")
    # Use xollvm's supported in-compiler extension. This also works when the OS
    # permits clang but blocks the separate opt executable; no policy is changed.
    plugin = [f"-fpass-plugin={args.plugin.resolve()}"] if args.plugin else []
    run([clang, *flags, *plugin, "-std=c++17", "-DCARDGUARD_XOLLVM=1", "-O1", "-S", "-emit-llvm",
         "-mllvm", "-enable-obfuscation", "-mllvm", "-obf-verify", "-mllvm", f"-obf-seed={args.seed}",
         "-mllvm", f"-obf-report-json={xollvm_report}",
         str(ROOT / "frontend" / "authorization_policy.cpp"), "-o", str(transformed)])
    run([clang, *flags, "-O2", "-S", "-emit-llvm", str(transformed), "-o", str(optimized)])
    details = json.loads(xollvm_report.read_text())
    verify_vm_report(details, args.target)
    ir = optimized.read_text()
    if "vm.bytecode" not in ir or "__vm_engine" not in ir:
        raise RuntimeError("Virtualization was skipped or optimized away; refusing an unprotected build.")
    if windows and '"cfguard"' not in ir:
        raise RuntimeError("Control Flow Guard metadata was lost during virtualization.")
    # Re-optimization is deliberately done before this step so the inspected IR is the codegen input.
    run([clang, *flags, "-O0", "-c", str(optimized), "-o", str(object_file)])
    report = {
        "xollvm_version": "0.11.1", "xollvm_source_commit": "eb0850bd7cc87f551ad2948826605e518f5b8aa2",
        "compiler": version, "mode": "clang-integrated", "target": args.target, "seed": args.seed,
        "scope": ["cardguard_policy_allows"], "rust_verifier": "statically-linked",
        "source_sha256": source_digest(), "object_sha256": digest(object_file),
        "optimized_ir_sha256": digest(optimized), "xollvm_report_sha256": digest(xollvm_report),
        "virtualization_survives_optimization": True, "cfg_metadata": windows,
        "unbreakable_claim": False,
    }
    protection_report.write_text(json.dumps(report, indent=2) + "\n")
    verify_artifact(output, args.target)
    print(f"Built and verified xollvm policy: {args.target}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"build-policy: {error}", file=sys.stderr)
        raise SystemExit(1)

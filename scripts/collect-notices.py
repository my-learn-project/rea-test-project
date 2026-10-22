"""Collect notices for a locked Windows/macOS Rust client, without network access.

Only LICENSE*/COPYING*/NOTICE* files and a crate's licenses/ directory are
eligible. No crate source tree, issuer files, private keys or build outputs are
copied. Run after the build has populated the current user's Cargo cache.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


DEFAULT_TARGET = "x86_64-pc-windows-msvc"
TARGETS = (DEFAULT_TARGET, "aarch64-apple-darwin", "x86_64-apple-darwin")
# Cargo can color only the duplicate marker even when the package/license text
# is plain. Strip complete terminal formatting before interpreting that marker.
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
DUPLICATE_MARKER = re.compile(r"(?:\s+\(\*\))+$")
PACKAGE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_-]*) "
    r"v(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"
    r"(?: \((?P<path>.+)\))?"
)
DENIED_SUFFIXES = {
    ".rs", ".c", ".cpp", ".h", ".hpp", ".toml", ".lock", ".exe", ".dll",
    ".pdb", ".key", ".pem", ".pfx", ".p12", ".dpapi", ".ps1", ".py",
}


def inside(path: Path, base: Path) -> Path:
    """Resolve both sides before any read/copy/write containment decision."""
    resolved = path.resolve()
    if not resolved.is_relative_to(base.resolve()):
        raise RuntimeError(f"Path escaped its allowed base: {path}")
    return resolved


def reject_output_links(path: Path, project: Path) -> None:
    """Do not let a junction/symlink redirect writes within the workspace."""
    lexical = Path(os.path.abspath(path))
    if not lexical.is_relative_to(project):
        raise RuntimeError(f"Output is outside the project: {path}")
    current = project
    for part in lexical.relative_to(project).parts:
        current /= part
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise RuntimeError(f"Refusing linked output component: {current}")


def default_output(project: Path, target: str) -> Path:
    if target == DEFAULT_TARGET:
        return project / "dist" / "client" / "licenses" / "rust"
    architecture = {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}[target]
    return project / "dist" / f"macos-{architecture}" / "CardGuard.app" / "Contents" / "Resources" / "licenses" / "rust"


def validate_output(path: Path, project: Path) -> Path:
    """Allow release/staging notice trees only, never arbitrary project writes."""
    reject_output_links(path, project)
    distribution = inside(project / "dist", project)
    output = inside(path, distribution)
    if output.relative_to(distribution).parts[-2:] != ("licenses", "rust"):
        raise RuntimeError("Notice output must be inside dist and end with licenses/rust")
    return output


def safe_component(component: str) -> None:
    if not component or component in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.+-]+", component):
        raise RuntimeError("Unsafe package path component")


def parse_tree(output: str, project: Path) -> list[dict]:
    packages: dict[tuple[str, str], dict] = {}
    for line in output.splitlines():
        line = ANSI_ESCAPE.sub("", line).strip()
        if any(ord(character) < 32 and character != "\t" for character in line):
            raise RuntimeError("Unexpected control characters in cargo tree output")
        if not line or line.startswith("["):
            continue
        if "|" not in line:
            raise RuntimeError(f"Unexpected cargo tree output: {line}")
        description, license_expression = line.split("|", 1)
        description = DUPLICATE_MARKER.sub("", description).replace(" (proc-macro)", "").strip()
        license_expression = " ".join(DUPLICATE_MARKER.sub("", license_expression).split())
        match = PACKAGE.fullmatch(description)
        if not match:
            raise RuntimeError(f"Cannot parse cargo package: {description}")
        name, version = match["name"], match["version"]
        safe_component(name)
        safe_component(version)
        local_path = match["path"]
        source = "registry-cache"
        if local_path:
            # Only this workspace is an expected non-registry source.
            inside(Path(local_path), project)
            source = "workspace"
        key = (name, version)
        item = {"name": name, "version": version, "license": license_expression or "UNKNOWN", "source": source}
        if key in packages and packages[key] != item:
            raise RuntimeError(f"Conflicting metadata for {name} {version}")
        packages[key] = item
    if not packages or not any(name == "license-client" for name, _ in packages):
        raise RuntimeError("cargo tree did not return the expected client package")
    return sorted(packages.values(), key=lambda item: (item["name"], item["version"]))


def notice_files(crate: Path) -> list[Path]:
    files: list[Path] = []
    for entry in sorted(crate.iterdir()):
        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
            if entry.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")) or entry.name.lower() == "licenses":
                raise RuntimeError(f"Refusing a linked notice path: {entry}")
            continue
        if entry.is_file() and entry.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
            files.append(inside(entry, crate))
        elif entry.is_dir() and entry.name.lower() == "licenses":
            for child in sorted(entry.rglob("*")):
                if child.is_symlink() or getattr(child, "is_junction", lambda: False)():
                    raise RuntimeError(f"Refusing a linked license directory member: {child}")
                if child.is_file():
                    files.append(inside(child, crate))
    for path in files:
        if path.suffix.lower() in DENIED_SUFFIXES or any(
            word in path.name.lower() for word in ("private", "passphrase", "secret", "credential")
        ):
            raise RuntimeError(f"Refusing source, executable or sensitive file in notices: {path.name}")
        if path.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError(f"Unexpectedly large notice file: {path.name}")
    return files


def write_text(path: Path, text: str, base: Path) -> None:
    target = inside(path, base)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise RuntimeError(f"Refusing linked output: {path}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def main() -> int:
    project = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo", help="Cargo executable in the initialized Rust environment")
    parser.add_argument("--cargo-home", type=Path, default=Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))))
    parser.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET,
                        help="Target dependency graph; defaults to the Windows client")
    parser.add_argument("--output", type=Path,
                        help="Notice directory inside dist, ending in licenses/rust; defaults to the target's release path")
    args = parser.parse_args()
    output = validate_output(args.output or default_output(project, args.target), project)
    registry = args.cargo_home.expanduser().resolve() / "registry" / "src"
    if not registry.is_dir():
        raise RuntimeError("Cargo registry source cache is missing; build the locked client first")
    command = [args.cargo, "tree", "--color", "never", "--locked", "--offline", "-p", "license-client", "--target", args.target,
               "--prefix", "none", "--format", "{p}|{l}"]
    environment = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never", NO_COLOR="1",
                       CARGO_HOME=str(args.cargo_home.expanduser().resolve()))
    result = subprocess.run(command, cwd=project, env=environment, check=True,
                            capture_output=True, text=True, encoding="utf-8", timeout=120)
    packages = parse_tree(result.stdout, project)
    output.mkdir(parents=True, exist_ok=True)
    incomplete: list[str] = []
    for package in packages:
        package["notices"] = []
        if package["source"] == "workspace":
            package["status"] = "workspace-project-license"
            continue
        dirname = f"{package['name']}-{package['version']}"
        candidates = []
        for namespace in sorted(registry.iterdir()):
            if not namespace.is_dir() or namespace.is_symlink() or getattr(namespace, "is_junction", lambda: False)():
                continue
            candidate = namespace / dirname
            if candidate.is_dir():
                if candidate.is_symlink() or getattr(candidate, "is_junction", lambda: False)():
                    raise RuntimeError(f"Refusing linked crate cache: {dirname}")
                candidates.append(inside(candidate, registry))
        if len(candidates) != 1:
            raise RuntimeError(f"Expected exactly one cached source for {dirname}; found {len(candidates)}")
        crate = candidates[0]
        package["registry_cache"] = crate.parent.name
        for source in notice_files(crate):
            relative = source.relative_to(crate)
            reject_output_links(output / dirname / relative, project)
            destination = inside(output / dirname / relative, output)
            if destination.is_symlink() or getattr(destination, "is_junction", lambda: False)():
                raise RuntimeError(f"Refusing linked notice destination: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            contents = source.read_bytes()
            destination.write_bytes(contents)
            package["notices"].append({"path": destination.relative_to(output).as_posix(),
                                        "sha256": hashlib.sha256(contents).hexdigest()})
        package["status"] = "copied" if package["notices"] else "missing-notice-files"
        if not package["notices"] or package["license"] == "UNKNOWN":
            incomplete.append(dirname)
    inventory = {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "target": args.target,
                 "package": "license-client", "command": command[1:], "network": "offline",
                 "complete": not incomplete, "needs_review": incomplete, "packages": packages}
    write_text(output / "inventory.json", json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", output)
    lines = ["# Rust 客户端依赖许可清单", "", f"目标平台：`{args.target}`。来源：锁定的离线 `cargo tree`。",
             "仅收集客户端依赖；工作区自己的组件适用项目许可。自动收集不替代发布许可审核。", "",
             "| 包 | 版本 | 许可证表达式 | 通知文件数 | 状态 |", "| --- | --- | --- | ---: | --- |"]
    for package in packages:
        expression = package["license"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {package['name']} | {package['version']} | {expression} | {len(package['notices'])} | {package['status']} |")
    if incomplete:
        lines += ["", "需补齐或人工审核：" + ", ".join(incomplete)]
    write_text(output / "inventory.md", "\n".join(lines) + "\n", output)
    print(f"Collected notices for {len(packages)} Rust client packages: {output}")
    if incomplete:
        print("Incomplete notices; review inventory.json before distribution.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"collect-notices: {error}", file=sys.stderr)
        raise SystemExit(1)

#!/bin/bash
# Run on macOS. Qt must be a shared macOS SDK; the app keeps the platform QStyle.
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo 'macOS builds require a Mac with Xcode Command Line Tools.' >&2
    exit 1
fi
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
arch="$(uname -m)"
skip_tests=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) arch="${2:?Missing architecture}"; shift 2 ;;
        --skip-tests) skip_tests=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
case "$arch" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) echo 'Architecture must be arm64 or x86_64.' >&2; exit 1 ;;
esac
if [[ "$arch" != "$(uname -m)" ]]; then
    echo 'Build each architecture on a matching Mac so native tests can run.' >&2
    exit 1
fi
: "${QT_ROOT:?Set QT_ROOT to the shared macOS Qt SDK directory.}"
qt_root="$(cd "$QT_ROOT" && pwd)"
[[ -x "$qt_root/bin/macdeployqt" && -x "$qt_root/bin/qmake" ]] || {
    echo 'QT_ROOT does not contain the macOS deployment tools.' >&2; exit 1;
}
for command in cargo rustup cmake ninja python3 xcrun codesign ditto; do
    command -v "$command" >/dev/null || { echo "Missing tool: $command" >&2; exit 1; }
done
xcrun --find clang++ >/dev/null
python3 - <<'PY'
from pathlib import Path
import re
key = Path('config/trusted-public-key.hex')
if not key.is_file() or not re.fullmatch(r'[0-9a-f]{64}', key.read_text().strip()):
    raise SystemExit('Provide config/trusted-public-key.hex with the existing issuer PUBLIC key.')
PY
rustup target add "$target"
if [[ "$skip_tests" == false ]]; then
    cargo fmt --all -- --check
    cargo clippy --locked --workspace --all-targets --target "$target" -- -D warnings
    cargo test --locked --workspace --target "$target"
fi
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
cargo build --locked --release --workspace --target "$target"
build_dir="$project_root/build/macos-$arch"
cmake -S . -B "$build_dir" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    "-DCMAKE_PREFIX_PATH=$qt_root" "-DCMAKE_OSX_ARCHITECTURES=$arch" \
    "-DCMAKE_OSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET"
cmake --build "$build_dir"

mkdir -p "$project_root/dist"
# Each build uses a new output directory, preserving earlier bundles.
stage="$(mktemp -d "$project_root/dist/macos-$arch-XXXXXX")"
app="$stage/CardGuard.app"
ditto "$build_dir/CardGuard.app" "$app"
cp "target/$target/release/license-client" "$app/Contents/MacOS/license-client"
chmod 755 "$app/Contents/MacOS/license-client"
license_dir="$app/Contents/Resources/licenses"
mkdir -p "$license_dir"
cp docs/THIRD_PARTY.md "$license_dir/"
cp docs/licenses/* "$license_dir/"
if [[ -d "$qt_root/licenses" ]]; then ditto "$qt_root/licenses" "$license_dir/qt"; fi
if [[ -d "$qt_root/share/licenses" ]]; then ditto "$qt_root/share/licenses" "$license_dir/qt-share"; fi
if [[ -d "$qt_root/sbom" ]]; then ditto "$qt_root/sbom" "$license_dir/qt-sbom"; fi
python3 scripts/collect-notices.py --target "$target" --output "$license_dir/rust"
qt_version="$("$qt_root/bin/qmake" -query QT_VERSION)"
python3 - "$app" "$target" "$qt_version" <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path
app, target, qt = sys.argv[1:]
info = {
    'target': target, 'qt_version': qt,
    'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'public_key_sha256': hashlib.sha256(bytes.fromhex(Path('config/trusted-public-key.hex').read_text().strip())).hexdigest(),
    'signing': 'developer-id' if os.environ.get('CARDGUARD_SIGN_IDENTITY') else 'ad-hoc',
    'notarized': False,
    'qt_source': f'https://download.qt.io/official_releases/qt/{qt.rsplit(".", 1)[0]}/{qt}/single/'
}
Path(app, 'Contents/Resources/build-info.json').write_text(json.dumps(info, indent=2) + '\n')
PY

if [[ -n "${CARDGUARD_SIGN_IDENTITY:-}" ]]; then
    codesign --force --options runtime --timestamp --sign "$CARDGUARD_SIGN_IDENTITY" "$app/Contents/MacOS/license-client"
    "$qt_root/bin/macdeployqt" "$app" -always-overwrite "-sign-for-notarization=$CARDGUARD_SIGN_IDENTITY"
else
    # Ad-hoc signatures are suitable for local testing, not Developer ID distribution.
    codesign --force --sign - "$app/Contents/MacOS/license-client"
    "$qt_root/bin/macdeployqt" "$app" -always-overwrite -codesign=-
fi
codesign --verify --deep --strict --verbose=2 "$app"
for binary in "$app/Contents/MacOS/CardGuard" "$app/Contents/MacOS/license-client"; do
    xcrun lipo "$binary" -verify_arch "$arch"
done
python3 scripts/test-macos.py --app "$app" --report "$build_dir/smoke-release.json"
archive="$stage/CardGuard-macos-$arch.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
(cd "$stage" && shasum -a 256 "CardGuard-macos-$arch.zip" > "CardGuard-macos-$arch.zip.sha256")
# Metadata is outside the signed app; CI uploads only the explicitly listed zip and digest.
python3 - "$app" "$archive" "$build_dir/artifact.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[3]).write_text(json.dumps({'app': sys.argv[1], 'archive': sys.argv[2]}) + '\n')
PY
echo "Built macOS client: $archive"

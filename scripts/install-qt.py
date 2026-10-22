"""Install Qt Widgets SDK from the official compiler-specific repository.

aqt 3.3 cannot address the new repository layout. Keep TLS and per-archive
upstream checksums enabled; only select Qt base/tools/translations archives.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from concurrent.futures import ThreadPoolExecutor

from defusedxml import ElementTree
import py7zr
import requests


def fetch(url: str) -> bytes:
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.content


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', default='6.12.0')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'6\.\d+\.\d+', args.version):
        raise ValueError('Expected a stable Qt 6 version')
    compact = args.version.replace('.', '')
    base = f'https://download.qt.io/online/qtsdkrepository/windows_x86/desktop/qt6_{compact}'
    layouts = [f'{base}/qt6_{compact}_msvc2022_64', f'{base}/qt6_{compact}']
    for repository in layouts:
        try:
            metadata = fetch(f'{repository}/Updates.xml')
            break
        except requests.HTTPError as exc:
            if exc.response.status_code != 404:
                raise
    else:
        raise RuntimeError('No official MSVC 2022 package metadata found')
    packages = ElementTree.fromstring(metadata)
    package_name = f'qt.qt6.{compact}.win64_msvc2022_64'
    package = next(p for p in packages.findall('PackageUpdate') if p.findtext('Name') == package_name)
    package_version = package.findtext('Version')
    names = [x.strip() for x in package.findtext('DownloadableArchives', '').split(',')]
    selected = [name for name in names if name.split('-')[0] in {'qtbase', 'qttools', 'qttranslations'}]
    if len(selected) != 3:
        raise RuntimeError('Required archives missing from Qt SDK metadata')
    if any(not re.fullmatch(r'[A-Za-z0-9_.-]+\.7z', name) for name in selected):
        raise RuntimeError('Unexpected archive filename in upstream metadata')
    args.output.mkdir(parents=True, exist_ok=True)
    cache = args.output.parent / 'downloads' / f'qt-{args.version}'
    cache.mkdir(parents=True, exist_ok=True)

    def download(name: str) -> Path:
        url = f'{repository}/{package_name}/{package_version}{name}'
        expected = fetch(url + '.sha1').decode('ascii').strip().split()[0].lower()
        if not re.fullmatch(r'[0-9a-f]{40}', expected):
            raise RuntimeError('Invalid upstream archive checksum')
        destination = cache / name
        if destination.exists() and hashlib.sha1(destination.read_bytes()).hexdigest() == expected:
            return destination
        print(f'Downloading {name}', flush=True)
        response = requests.get(url, stream=True, timeout=120)
        response.raise_for_status()
        temporary = destination.with_suffix('.part')
        digest = hashlib.sha1()
        with temporary.open('wb') as output:
            for chunk in response.iter_content(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise RuntimeError(f'Checksum mismatch: {name}')
        temporary.replace(destination)
        return destination

    with ThreadPoolExecutor(max_workers=3) as pool:
        archives = list(pool.map(download, selected))
    for path in archives:
        print(f'Extracting {path.name}', flush=True)
        with py7zr.SevenZipFile(path) as archive:
            for name in archive.getnames():
                resolved = (args.output / name).resolve()
                if not resolved.is_relative_to(args.output.resolve()):
                    raise RuntimeError('Unsafe archive path')
            archive.extractall(args.output)
    qt_root = args.output.resolve()
    if not (qt_root / 'bin' / 'qmake.exe').exists():
        raise RuntimeError('Unexpected SDK archive directory layout')
    (qt_root / 'bin' / 'qt.conf').write_text('[Paths]\nPrefix=..\n', encoding='utf-8')
    environment = {'qtRoot': str(qt_root), 'qtVersion': args.version,
                   'python': str(Path(os.sys.executable).resolve())}
    (args.output.parent / 'environment.json').write_text(json.dumps(environment, indent=2), encoding='utf-8')
    print(f'Qt SDK ready: {qt_root}', flush=True)


if __name__ == '__main__':
    main()

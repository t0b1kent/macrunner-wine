#!/usr/bin/env python3
"""Fetch and verify the public, fixed 20260505 universal macOS PE toolchain."""
import hashlib
from pathlib import Path
import tarfile
import urllib.request

root = Path(__file__).resolve().parent.parent / '_toolchain'
version = 'llvm-mingw-20260505-ucrt-macos-universal'
digest = '050379de888f0c843787819dadf183df3693330a5724643919e9121f16355295'
url = 'https://github.com/mstorsjo/llvm-mingw/releases/download/20260505/' + version + '.tar.xz'
root.mkdir(exist_ok=True)
archive = root / (version + '.tar.xz')
if not archive.exists():
    with urllib.request.urlopen(url, timeout=120) as response, archive.open('wb') as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
with archive.open('rb') as stream:
    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
if actual != digest:
    raise SystemExit('llvm-mingw archive SHA256 mismatch; discard the download and retry')
if not (root / version / 'bin/clang').exists():
    with tarfile.open(archive) as source:
        source.extractall(root, filter='data')
print('llvm-mingw 20260505 verified: ' + digest)

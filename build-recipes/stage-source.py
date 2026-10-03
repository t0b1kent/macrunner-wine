#!/usr/bin/env python3
"""Preserve archived Wine bytes and their original sibling include layout."""
from pathlib import Path
import shutil
import sys

root = Path(__file__).resolve().parent.parent
build = Path(sys.argv[1]).resolve()
assert build != root, 'Use a distinct build directory'
ignored = {'.git', '.github', 'docs', 'build-recipes', 'third_party', '_build', '_install', '_toolchain', '__pycache__'}
if root in build.parents:
    ignored.add(build.relative_to(root).parts[0])
shutil.copytree(root, build / 'source-wine', dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(*ignored))
shutil.copytree(root / 'third_party/hyperbridge/include', build / 'hyperbridge/include', dirs_exist_ok=True)
shutil.copytree(root / 'third_party/hyperbridge/src', build / 'hyperbridge/src', dirs_exist_ok=True)
shutil.copy2(root / 'build-recipes/ntdll-include/hb_probe.h', build / 'hyperbridge/include/hb_probe.h')
print('Archived Wine source staged with its relative HyperBridge dependency')

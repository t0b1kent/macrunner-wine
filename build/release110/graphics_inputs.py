#!/usr/bin/env python3
"""Restore the three pinned source-build outputs for the existing graphics producer."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import zipfile

REPO = 't0b1kent/macrunner-wine'
INPUTS = {
    'wine': dict(run=41880058774, revision='0db5d3a80e302315a1dc37e8f6e1bba551310430',
                 artifact=13353797184, sha256='a10ceeedbe6700575cf57d83145fdebc169c8e147df33bbc7a92ed367aa9ae6b'),
    'deps': dict(run=38515047558, revision='797285393a8e87ff5b4c24ece8c0696453c706c0',
                 artifact=11874722836, sha256='aba1cf1ac2052b0d66c955a0dd2be6dc9beb151147ae5f3ed629a3fbc8208040'),
    'llvm': dict(run=41886099253, revision='d65b41b54dc3bd9c549565444eb53176b167bb57',
                 artifact=13353673861, sha256='be54d1547590ed4507d0ed9b8880ee80a9b12673564bb0988c6871310e3274d0'),
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def api(endpoint):
    return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPO + endpoint], timeout=120))


def unpack_zip(archive, destination):
    with zipfile.ZipFile(archive) as stream:
        rows = stream.infolist()
        if len(rows) > 300000 or sum(r.file_size for r in rows) > 3 * 1024**3:
            raise ValueError('Artifact zip exceeds extraction cap')
        for row in rows:
            path = PurePosixPath(row.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in row.filename or stat.S_ISLNK(row.external_attr >> 16):
                raise ValueError('Unsafe artifact member: ' + row.filename)
        stream.extractall(destination)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def only(root, pattern):
    rows = list(root.rglob(pattern))
    if len(rows) != 1:
        raise ValueError('Expected exactly one ' + pattern + ', got ' + str(len(rows)))
    return rows[0]


def restore(args):
    root = args.work.resolve()
    root.mkdir(parents=True, exist_ok=False)
    reports = root / 'reports'; reports.mkdir()
    result = dict(status='STARTED', first_failure=None, inputs={}, paths={})
    try:
        archive_driver = module('graphics_archive_driver', args.dxmt / 'build/repro109dxmt/repro109_dxmt_after_wine27.py')
        for name, pin in INPUTS.items():
            run = api('/actions/runs/' + str(pin['run']))
            if run['head_sha'] != pin['revision'] or run['status'] != 'completed':
                raise ValueError(name + ' producer revision/state differs')
            if name == 'deps':
                jobs = api('/actions/runs/' + str(pin['run']) + '/jobs?per_page=100')['jobs']
                if not any(j['name'] == 'deps' and j['conclusion'] == 'success' for j in jobs):
                    raise ValueError('Dependency job did not succeed')
            elif run['conclusion'] != 'success':
                raise ValueError(name + ' producer did not succeed')
            metadata = api('/actions/artifacts/' + str(pin['artifact']))
            if metadata['expired'] or metadata['workflow_run']['id'] != pin['run'] or metadata['digest'] != 'sha256:' + pin['sha256']:
                raise ValueError(name + ' artifact identity differs')
            (reports / (name + '-artifact.json')).write_text(json.dumps(metadata, indent=2) + '\n')
            archive = root / (name + '.zip')
            with archive.open('xb') as stream:
                subprocess.run(['gh', 'api', 'repos/' + REPO + '/actions/artifacts/' + str(pin['artifact']) + '/zip'],
                               stdout=stream, stdin=subprocess.DEVNULL, check=True, timeout=900)
            if sha(archive) != pin['sha256']:
                raise ValueError(name + ' artifact bytes differ')
            unpacked = root / name
            unpack_zip(archive, unpacked)
            result['inputs'][name] = dict(pin, zip_bytes=archive.stat().st_size)
        temp = Path(os.environ['RUNNER_TEMP'])
        paths = dict(wine=temp / 'repro110-wine-c12-work/wine/install',
                     deps=temp / 'repro110-wine-c12-work/deps/prefix',
                     moltenvk=temp / 'repro110-wine-c12-work/moltenvk/prefix',
                     llvm=temp / 'release110-llvm15/prefix')
        for name, kind, filename in [('wine', 'wine', 'wine-dist.tar.gz'),
                                      ('deps', 'deps', 'dependency-prefix.tar.gz'),
                                      ('moltenvk', 'deps', 'moltenvk-prefix.tar.gz'),
                                      ('llvm', 'llvm', 'llvm15-prefix.tar.gz')]:
            archive = only(root / kind, filename)
            actual = sha(archive)
            if name == 'llvm' and actual != '157fc4aba1f0c5a9db97ca01b13a7b3933f5402359de30098f32e1abe2e162bc':
                raise ValueError('LLVM tar differs from the successful producer output')
            if name != 'llvm':
                if Path(str(archive) + '.sha256').read_text().split()[0] != actual:
                    raise ValueError(name + ' tar sidecar differs')
            archive_driver.unpack(archive, actual, paths[name])
            result['inputs'][kind][name + '_tar_sha256'] = actual
        expected = [('wine', 'FULL_WINE_SOURCE_BUILT_NOT_ACCEPTED'),
                    ('llvm', 'LLVM15_ARM64_SOURCE_BUILT_NOT_DXMT_ACCEPTED')]
        for name, status in expected:
            matches = []
            for report in (root / name).rglob('RESULT.json'):
                value = json.loads(report.read_text())
                if value.get('status') == status:
                    matches.append(value)
                    (reports / (name + '-producer.json')).write_text(json.dumps(value, indent=2) + '\n')
            if len(matches) != 1 or matches[0].get('install_skipped') != 0:
                raise ValueError(name + ' successful producer receipt missing or install skipped')
        wine_builder = module('graphics_wine_builder', args.wine / 'build/repro110wine/build_wine.py')
        compiler = json.loads((args.wine / 'build/repro110wine/full.lock.json').read_text())['compiler']
        archive = root / 'llvm-mingw.tar.xz'
        wine_builder.download_compiler(compiler, archive, reports)
        paths['compiler'] = wine_builder.prepare_compiler(archive, root / 'compiler', compiler['sha256'], reports)
        paths['meson'] = paths['deps'] / 'bin/meson'
        paths['ninja'] = paths['deps'] / 'bin/ninja'
        result['paths'] = {k: str(v) for k, v in paths.items()}
        result['status'] = 'SOURCE_BUILD_INPUTS_RESTORED_NOT_GRAPHICS_ACCEPTED'
        return 0
    except Exception as error:
        result.update(status='FAILED', first_failure=str(error))
        return 1
    finally:
        (reports / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(dict(status=result['status'], first_failure=result['first_failure'])), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--wine', type=Path, required=True)
    parser.add_argument('--dxmt', type=Path, required=True)
    raise SystemExit(restore(parser.parse_args()))

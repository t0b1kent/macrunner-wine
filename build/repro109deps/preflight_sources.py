#!/usr/bin/env python3
"""Cloud-only source acquisition. No configure, compiler, install or source execution."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_deps as dep


def sha(path):
    return dep.file_sha(path)


def identity():
    return {name: sha(HERE / name) for name in
            ('deps.lock.json', 'download-sizes.lock.json', 'source-routes.lock.json')}


def git_identity(source):
    command = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
               '-C', str(source)]
    env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', GIT_TERMINAL_PROMPT='0',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    values = {}
    for key, argv in [('revision', ['rev-parse', 'HEAD']),
                      ('revision_count', ['rev-list', '--count', 'HEAD']),
                      ('dirty', ['status', '--porcelain', '--untracked-files=all'])]:
        result = subprocess.run(command + argv, env=env, capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError('Prepared Git input identity command failed: ' + key)
        values[key] = result.stdout.decode().strip()
    return values


def validate(root, lock):
    """Rehash every sealed source before the consumer invokes any compiler."""
    root = Path(root).resolve()
    receipt = json.loads((root / 'reports/RESULT.json').read_bytes())
    rows = lock['components']
    if (receipt.get('status') != 'ALL_SOURCE_INPUTS_PRESENT_NOT_BUILT' or
            receipt.get('locks') != identity() or
            set(receipt.get('components', {})) != {r['name'] for r in rows} or
            receipt.get('requested_components') != len(rows) or receipt.get('failed_components') != 0):
        raise ValueError('Prepared source set is incomplete or belongs to another lock')
    errors = []
    for row in rows:
        name = row['name']
        path = root / (name + '.source.tar')
        item = receipt['components'][name]
        try:
            if (path.is_symlink() or not path.is_file() or item.get('state') != 'PRESENT' or
                    not 0 < path.stat().st_size <= dep.MAX_ARCHIVE or
                    item.get('bytes') != path.stat().st_size or
                    item.get('sha256') != row['sha256'] or sha(path) != row['sha256']):
                raise ValueError('Prepared archive bytes differ')
            if row.get('source_kind') == 'git':
                source = root / (name + '-source')
                actual = git_identity(source)
                expected = dict(revision=row['revision'], revision_count=str(row['revision_count']), dirty='')
                if actual != expected or item.get('git') != expected:
                    raise ValueError('Prepared Git checkout differs')
        except Exception as error:
            errors.append(dict(component=name, error=str(error)))
    if errors:
        raise ValueError('Prepared source verification failed: ' + json.dumps(errors))
    return receipt


def copy_source(row, root, destination, work):
    """Consumer calls validate once before creating its build tree."""
    source_archive = Path(root) / (row['name'] + '.source.tar')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Prepared source destination already exists')
    shutil.copyfile(source_archive, destination)
    if sha(destination) != row['sha256']:
        raise ValueError('Prepared archive changed during copy')
    if row.get('source_kind') == 'git':
        source = Path(work) / (row['name'] + '-source')
        shutil.copytree(Path(root) / source.name, source, symlinks=True)
        if git_identity(source) != dict(revision=row['revision'],
                revision_count=str(row['revision_count']), dirty=''):
            raise ValueError('Prepared Git checkout changed during copy')
        return source
    return dep.unpack(destination, Path(work) / (row['name'] + '-source'))


def extract_inputs(archive, destination, lock):
    destination = Path(destination).resolve()
    if destination.exists() or destination.is_symlink():
        raise ValueError('Prepared source extraction destination already exists')
    with tarfile.open(archive, 'r:*') as source:
        members = source.getmembers()
        if len(members) > 50000 or sum(m.size for m in members) > dep.MAX_EXPANDED:
            raise ValueError('Prepared source archive expansion cap exceeded')
        destination.mkdir(parents=True)
        source.extractall(destination, members=members, filter='data')
    return validate(destination, lock)


def collect(root, lock, workers=8, minutes=10):
    dep.cloud_guard(lock['toolchain'])
    root = Path(root).resolve()
    if root.exists() or any(c.isspace() for c in str(root)):
        raise ValueError('Fresh source-only work path without whitespace required')
    if type(workers) is not int or not 1 <= workers <= 8 or not 1 <= minutes <= 15:
        raise ValueError('Source preflight limits refused')
    root.mkdir(parents=True)
    out = root / 'reports'; out.mkdir()
    start = time.monotonic(); deadline = start + minutes * 60
    rows = lock['components']
    result = dict(schema=1, status='SOURCE_INPUTS_STARTED', locks=identity(),
                  requested_components=len(rows), archive_components=sum(r.get('source_kind') != 'git' for r in rows),
                  git_components=sum(r.get('source_kind') == 'git' for r in rows),
                  components={}, first_failure=None, failures=[], install_skipped=0,
                  configure='NOT_ENABLED', compilation='NOT_ENABLED', installation='NOT_ENABLED',
                  source_execution='NOT_ENABLED', games='NOT_ENABLED')

    def acquire(row):
        name = row['name']; archive = root / (name + '.source.tar')
        if time.monotonic() >= deadline:
            return dict(component=name, state='NOT_ENABLED', error='Input preflight deadline before transfer')
        try:
            if row.get('source_kind') == 'git':
                env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', GIT_TERMINAL_PROMPT='0',
                           GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
                source = dep.git_source(row, root, archive, env, out, deadline)
                git = git_identity(source)
                expected = dict(revision=row['revision'], revision_count=str(row['revision_count']), dirty='')
                if git != expected:
                    raise ValueError('Git input revision/history/worktree differs')
                transfer = dict(git=git)
            else:
                transfer = dict(transport=dep.source_download.download(row, archive, out))
            if sha(archive) != row['sha256']:
                raise ValueError('Final source archive SHA differs')
            return dict(component=name, state='PRESENT', bytes=archive.stat().st_size,
                        sha256=sha(archive), **transfer)
        except Exception as error:
            return dict(component=name, state='FAILED', error=str(error))

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            tasks = {pool.submit(acquire, row): row['name'] for row in rows}
            for task in as_completed(tasks):
                item = task.result(); result['components'][item['component']] = item
                if item['state'] != 'PRESENT':
                    result['failures'].append(item)
                    if result['first_failure'] is None:
                        result['first_failure'] = item
        result['present_components'] = sum(v['state'] == 'PRESENT' for v in result['components'].values())
        result['failed_components'] = len(result['failures'])
        result['status'] = ('ALL_SOURCE_INPUTS_PRESENT_NOT_BUILT' if result['present_components'] == len(rows)
                            else 'SOURCE_INPUTS_FAILED_NO_BUILD')
    finally:
        result['elapsed_seconds'] = time.monotonic() - start
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: result.get(k) for k in ('status', 'requested_components',
              'present_components', 'failed_components', 'elapsed_seconds', 'first_failure')}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--minutes', type=int, default=10)
    parser.add_argument('--extract', type=Path, help='Unpack the same-run verified input artifact')
    args = parser.parse_args()
    # Reuse the full recipe's selected cloud profile and its source-file checks.
    sys.path.insert(0, str(HERE.parent / 'repro109wine'))
    import build_full
    build_full.check_inputs()
    lock = build_full.apply_profile(dep.read_lock(), 'github-xcode27-arm64')
    if args.extract is not None:
        dep.cloud_guard(lock['toolchain'])
        extract_inputs(args.extract, args.work, lock)
        print(json.dumps(dict(status='PREPARED_SOURCES_REHASHED_NOT_BUILT', components=len(lock['components']))))
        return 0
    result = collect(args.work, lock, args.workers, args.minutes)
    return 0 if result['status'] == 'ALL_SOURCE_INPUTS_PRESENT_NOT_BUILT' else 1


if __name__ == '__main__':
    raise SystemExit(main())

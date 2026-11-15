#!/usr/bin/env python3
"""Reuse the completed c33r dependency job while its independent Wine job continues."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

PIN = dict(run=43698198024, revision='12b358f5442a32fcb320fb0118fad47068d746cf',
           artifact=14158363957, sha256='da22fa1197b3bf83e9a28087572759ef9a37bf8f38a76185be1842088e500000')


def check_producer(run, jobs, artifact):
    if run['head_sha'] != PIN['revision']:
        raise ValueError('Dependency source revision differs')
    if not any(j['name'] == 'deps' and j['status'] == 'completed' and j['conclusion'] == 'success' for j in jobs):
        raise ValueError('The complete dependency job must succeed')
    if (artifact['id'] != PIN['artifact'] or artifact['expired'] or
            artifact['workflow_run']['id'] != PIN['run'] or artifact['digest'] != 'sha256:' + PIN['sha256']):
        raise ValueError('Dependency artifact identity differs')


def restore(args):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('Dependency restoration requires the ARM64 cloud worker')
    args.work.mkdir(parents=True, exist_ok=False)
    reports = args.work / 'reports'; reports.mkdir()
    result = dict(status='STARTED', failure=None, pin=PIN)
    try:
        spec = importlib.util.spec_from_file_location('indiana_transport', args.transport)
        transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
        run = transport.api('/actions/runs/' + str(PIN['run']))
        jobs = transport.api('/actions/runs/' + str(PIN['run']) + '/jobs?per_page=100')['jobs']
        artifact = transport.api('/actions/artifacts/' + str(PIN['artifact']))
        check_producer(run, jobs, artifact)
        (reports / 'artifact.json').write_text(json.dumps(artifact, indent=2) + '\n')
        (reports / 'dependency-job.json').write_text(json.dumps([j for j in jobs if j['name'] == 'deps'], indent=2) + '\n')
        archive = args.work / 'deps.zip'
        transport.download_artifact(PIN['artifact'], archive, PIN['sha256'], reports)
        unpacked = args.work / 'deps'
        transport.unpack_zip(archive, unpacked)
        prefix_archive = transport.only(unpacked, 'dependency-prefix.tar.gz')
        digest = transport.sha(prefix_archive)
        if Path(str(prefix_archive) + '.sha256').read_text().split()[0] != digest:
            raise ValueError('Dependency prefix sidecar differs')
        driver = transport.module('indiana_archive_reader', args.dxmt / 'build/repro109dxmt/repro109_dxmt_after_wine27.py')
        prefix = Path(os.environ['RUNNER_TEMP']) / 'repro110-wine-c12-work/deps/prefix'
        driver.unpack(prefix_archive, digest, prefix)
        tools = {}
        for name in ['cmake', 'ninja']:
            path = prefix / 'bin' / name
            if not path.is_file() or path.is_symlink() or struct.unpack('<II', path.read_bytes()[:8]) != (0xfeedfacf, 0x0100000c):
                raise ValueError('Expected source-built ARM64 tool missing: ' + name)
            version = subprocess.check_output([str(path), '--version'], text=True, timeout=30).strip()
            tools[name] = dict(path=str(path), sha256=transport.sha(path), version=version)
        for index, path in enumerate(sorted(unpacked.rglob('RESULT.json'))):
            (reports / ('producer-' + str(index) + '.json')).write_bytes(path.read_bytes())
        result.update(status='INDIANA_SOURCE_BUILT_TOOLS_RESTORED', prefix_tar_sha256=digest, tools=tools)
    except Exception as error:
        result.update(status='FAILED', failure=str(error))
    (reports / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return int(result['failure'] is not None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport', required=True, type=Path)
    parser.add_argument('--dxmt', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    raise SystemExit(restore(parser.parse_args()))

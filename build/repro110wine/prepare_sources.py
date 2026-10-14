#!/usr/bin/env python3
"""Cloud-only acquisition of the 47 dependency sources with the c12 transport policy (see source_transport.py).

Same job as repro109deps/preflight_sources.py: acquire and rehash, never configure or compile. The differences are the
transport (redirects accepted when the pinned digest matches, pauses before retries, HTTP/1.1, resume after a cut)
and a profile option, so that the second Wine chain can run it on its own runner image. The shared drivers are loaded
unchanged; only the transport name inside source_download is replaced.
"""
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_full as full
import source_transport

PROFILES = ('github-xcode27-arm64', 'github-macos26-arm64', 'github-macos15-arm64')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--minutes', type=int, default=10)
    parser.add_argument('--extract', type=Path, help='Unpack the same-run verified input artifact instead of downloading')
    parser.add_argument('--profile', choices=PROFILES, default='github-xcode27-arm64')
    args = parser.parse_args(argv)
    full.check_inputs()
    preflight = full.load_driver('repro110_prepare_preflight', full.REPO / 'repro109deps/preflight_sources.py')
    dep = preflight.dep
    source_transport.install(dep.source_download)
    lock = full.apply_profile(dep.read_lock(), args.profile)
    if args.extract is not None:
        dep.cloud_guard(lock['toolchain'])
        preflight.extract_inputs(args.extract, args.work, lock)
        print(json.dumps(dict(status='PREPARED_SOURCES_REHASHED_NOT_BUILT', components=len(lock['components']))))
        return 0
    result = preflight.collect(args.work, lock, args.workers, args.minutes)
    reports = Path(args.work).resolve() / 'reports'
    summary = source_transport.summarize(reports)
    (reports / 'source-transport-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: summary[key] for key in ('redirected', 'retried', 'resumed', 'failed')}))
    return 0 if result['status'] == 'ALL_SOURCE_INPUTS_PRESENT_NOT_BUILT' else 1


if __name__ == '__main__':
    raise SystemExit(main())

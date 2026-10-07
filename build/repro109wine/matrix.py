#!/usr/bin/env python3
"""Run independent prerequisites through the existing pinned Wine producers."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_full as full

STAGES = ('sdk', 'deps10', 'moltenvk2', 'compiler')
PROFILE = 'github-xcode27-arm64'


def skipped_lines(root):
    count = 0
    for directory in (root / 'reports', root / 'deps/reports', root / 'moltenvk/reports'):
        for path in directory.glob('*.log'):
            with path.open(errors='replace') as stream:
                count += sum('install skipped' in line.lower() for line in stream)
    return count


def run_stage(args, lock):
    full.cloud_guard(PROFILE)
    full.require(args.stage in STAGES and 1 <= args.jobs <= 8, 'Invalid stage or jobs')
    root = args.work.resolve()
    full.require(not root.exists(), 'Fresh stage work required; no overwrite/retry')
    full.require(not any(char.isspace() for char in str(root)), 'Work path contains whitespace')
    root.mkdir(parents=True)
    out = root / 'reports'
    out.mkdir()
    result = dict(schema=1, selected_stage=args.stage, profile=PROFILE, state='STARTED',
                  first_failure=None, product_install='SKIPPED', comparison='NOT_ENABLED',
                  stands='NOT_ENABLED', games='NOT_ENABLED', signing='NOT_ENABLED',
                  classification='DIAGNOSTIC_ONLY_NOT_GOLDEN',
                  dependency_scope='All 47 components; independent branches continue on failure')
    started = time.monotonic()
    try:
        if args.stage == 'sdk':
            dep = full.load_driver('matrix_sdk_deps', full.REPO / 'repro109deps/build_deps.py')
            selected = full.apply_profile(dep.read_lock(), PROFILE)
            sdk, _, _ = dep.toolchain_preflight(selected['toolchain'], out)
            result['producer'] = full.check_sdk_exports(sdk, out)
        elif args.stage == 'deps10':
            dep = full.load_driver('matrix_source_deps', full.REPO / 'repro109deps/build_deps.py')
            selected = full.apply_profile(dep.read_lock(), PROFILE)
            dep.build(SimpleNamespace(work=root / 'deps', jobs=args.jobs, minutes=95), selected)
            produced = json.loads((root / 'deps/reports/RESULT.json').read_bytes())
            full.require(not produced['failed_components'] and not produced['skipped_components']
                         and produced['built_components'] == len(selected['components']),
                         'Dependency stage incomplete')
            result['producer'] = produced
        elif args.stage == 'moltenvk2':
            mv = full.load_driver('matrix_source_moltenvk', full.REPO / 'repro109moltenvk/build_moltenvk.py')
            mv.build(SimpleNamespace(work=root / 'moltenvk', jobs=args.jobs, minutes=60),
                     full.apply_profile(mv.read_lock(), PROFILE))
            produced = json.loads((root / 'moltenvk/reports/RESULT.json').read_bytes())
            full.require(produced['source_built'] and produced['first_failure'] is None
                         and produced['install_skipped'] == 0, 'MoltenVK stage incomplete')
            result['producer'] = produced
        else:
            wine = full.load_driver('matrix_compiler_wine', HERE / 'build_wine.py')
            dep = full.load_driver('matrix_compiler_deps', full.REPO / 'repro109deps/build_deps.py')
            compiler = root / 'llvm-mingw.tar.xz'
            wine.download_compiler(lock['compiler'], compiler, out)
            llvm = wine.prepare_compiler(compiler, root / 'toolchain', lock['compiler']['sha256'], out)
            deadline = time.monotonic() + 300
            versions = {}
            for tool, expected in [('clang', '22.1.5'), ('ld.lld', '22.1.5')]:
                log = out / (tool + '-version.log')
                dep.command([str(llvm / 'bin' / tool), '--version'], root, None,
                            log, out, 'compiler:' + tool, deadline, timeout=30)
                value = log.read_text()
                full.require(expected in value, 'Pinned compiler version differs: ' + tool)
                versions[tool] = value
            result['producer'] = dict(archive_sha256=dep.file_sha(compiler),
                                      versions=versions, layout_report='compiler-archive.json')
        result['state'] = 'STAGE_COMPLETED_NOT_ACCEPTED'
    except Exception as error:
        result.update(state='FAILED', first_failure=dict(stage=args.stage, error=str(error)))
        raise
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        result['install_skipped_lines'] = skipped_lines(root)
        (out / 'MATRIX-RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({key: result[key] for key in
                          ['selected_stage', 'state', 'install_skipped_lines', 'product_install']}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--stage', choices=STAGES)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--jobs', type=int, default=3)
    args = parser.parse_args()
    lock = full.check_inputs()
    if args.check_inputs:
        print(json.dumps(dict(state='PLAN_ONLY', stages=STAGES, builds=0, downloads=0, install='skipped')))
        return 0
    if args.stage is None or args.work is None:
        parser.error('--stage and --work are required')
    try:
        run_stage(args, lock)
        return 0
    except Exception as error:
        print('Wine prerequisite failed; complete evidence in driver log and MATRIX-RESULT.json',
              file=sys.stderr)
        raise


if __name__ == '__main__':
    raise SystemExit(main())

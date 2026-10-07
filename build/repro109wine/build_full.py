#!/usr/bin/env python3
"""Fresh cloud source builds: deps10 -> stock MoltenVK -> complete Wine.

Keep the deps install prefix in place: its binaries/configuration may contain
absolute paths. Import only MoltenVK runtime/API/pkg-config/license outputs.
The two original manifests remain byte-exact evidence, not rewritten claims.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
sys.dont_write_bytecode = True
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_driver(name, path):
    # -I excludes the script directory; shared drivers import source_fixes.
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check_inputs():
    lock = json.loads((HERE / 'full.lock.json').read_bytes())
    require(lock['schema'] == 1, 'Unexpected full build lock schema')
    for name, expected in lock['files'].items():
        require(digest((REPO / name).read_bytes()) == expected, 'Pinned driver/lock drift: ' + name)
    wine = json.loads((HERE / 'wine.lock.json').read_bytes())
    require(lock['compiler']['sha256'] == wine['toolchain']['llvm_mingw_sha256'], 'Compiler locks differ')
    fex = json.loads((REPO / 'repro109/fex64.lock.json').read_bytes())
    require(lock['compiler'] == dict(name='llvm-mingw', url=fex['llvm_mingw_url'],
            sha256=fex['llvm_mingw_sha256'], size=fex['llvm_mingw_size']), 'Compiler publisher/size pins differ')
    # The outer lock can match while MoltenVK still pins an older shared recipe.
    # Validate with the actual consumer before expensive dependency compilation.
    moltenvk = load_driver('repro109_full_moltenvk_inputs', REPO / 'repro109moltenvk/build_moltenvk.py')
    moltenvk.read_lock()
    return lock


def apply_profile(source_lock, profile):
    value = copy.deepcopy(source_lock)
    if profile in ['github-macos15-arm64', 'github-xcode27-arm64']:
        filename = 'github-xcode27.lock.json' if profile == 'github-xcode27-arm64' else 'github-macos15.lock.json'
        selected = json.loads((HERE / filename).read_bytes())
        previous = value['toolchain']
        value['toolchain'] = dict(selected['toolchain'])
        value['toolchain'].update({k: v for k, v in previous.items() if k.startswith('llvm_mingw')})
        return value
    if profile == 'github':
        return value
    require(profile == 'xcode-cloud', 'Unexpected full Wine cloud profile')
    selected = json.loads((REPO / 'repro109deps/xcode-cloud.lock.json').read_bytes())
    previous = value['toolchain']
    value['toolchain'] = dict(selected, deployment_target=previous.get('deployment_target', '14.0'))
    value['toolchain'].update({k: v for k, v in previous.items() if k.startswith('llvm_mingw')})
    return value


def cloud_guard(profile):
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Cloud requires Darwin arm64')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' or
            (os.environ.get('CI_WORKSPACE_PATH') and os.environ.get('CI_PRIMARY_REPOSITORY_PATH')),
            'Source execution/download allowed only in the cloud')
    require(profile in ['github', 'github-macos15-arm64', 'github-xcode27-arm64', 'xcode-cloud'], 'Unexpected full Wine cloud profile')
    if profile == 'xcode-cloud':
        require(bool(os.environ.get('CI_BUILD_NUMBER')), 'Xcode Cloud build number required')
        require(sys.version_info >= (3, 9), 'Use selected Apple Python >=3.9')
    else:
        require(platform.python_version() == '3.13.7', 'Use pinned Python 3.13.7')
    # Repository visibility/publication belongs to jobs/repro109-wine-full.sh.
    # The same pinned source builder must also run in a user's cloud checkout.


def check_sdk_exports(sdk, out):
    """Reject a missing Wine x18 ABI before any dependency download or build."""
    symbols = ['_os_custom_x18_abi_enabled', '_os_set_custom_x18_abi_enabled']
    matches = {symbol: [] for symbol in symbols}
    for path in sorted((sdk / 'usr/lib/system').glob('*.tbd')):
        raw = path.read_bytes()
        for symbol in symbols:
            pattern = rb'(?<![A-Za-z0-9_])' + re.escape(symbol.encode()) + rb'(?![A-Za-z0-9_])'
            if re.search(pattern, raw):
                matches[symbol].append(dict(path=str(path.relative_to(sdk)), sha256=digest(raw)))
    status = 'PRESENT' if all(matches.values()) else 'EMPTY'
    receipt = dict(status=status, sdk=str(sdk), exports=matches,
                   counts={key: len(value) for key, value in matches.items()},
                   source_downloads=0, compilation=0)
    (out / 'sdk-x18-exports.json').write_text(json.dumps(receipt, indent=2) + '\n')
    require(status == 'PRESENT', 'Pinned SDK lacks Wine x18 ABI exports: ' +
            ', '.join(key for key, value in matches.items() if not value))
    return receipt


def compose(prefix, deps_manifest, molten_prefix, molten_manifest, out, dep, wine):
    deps_raw, molten_raw = deps_manifest.read_bytes(), molten_manifest.read_bytes()
    base, molten = json.loads(deps_raw), json.loads(molten_raw)
    require(base['schema'] == molten['schema'] == 1, 'Manifest schemas differ')
    require(base['source_built'] is True and base['status'] == 'PARTIAL_DEPENDENCIES_BUILT_NOT_WINE_READY',
            'deps8 did not finish every requested component')
    require(not base['failures'] and not base['skipped_components'] and base['install_skipped'] == 0,
            'deps8 contains failed/skipped work or install skipped')
    require(molten['source_built'] is True and molten['status'] == 'MOLTENVK_SOURCE_BUILT_NOT_INDIANA_ACCEPTANCE'
            and molten['first_failure'] is None and molten['install_skipped'] == 0,
            'MoltenVK2 did not finish its stock source build')
    require(base['files'] == dep.inventory(prefix), 'deps8 prefix differs from its raw inventory')
    require(molten['files'] == dep.inventory(molten_prefix), 'MoltenVK prefix differs from its raw inventory')
    require(set(base['remaining_wine_required']) == {'MoltenVK'}, 'Unexpected remaining Wine requirements')
    require('MoltenVK' not in base['components'], 'MoltenVK component already present')
    mv_lock_raw = (REPO / 'repro109moltenvk/moltenvk.lock.json').read_bytes()
    mv_lock = json.loads(mv_lock_raw)
    require(molten['lock_sha256'] == digest(mv_lock_raw), 'MoltenVK source lock drift')
    source_rows = {row['name']: row for row in molten['sources']}
    bootstrap = {row['name']: row for row in json.loads((REPO / 'repro109deps/deps.lock.json').read_bytes())['components']}
    names = {'MoltenVK', 'cmake', 'ninja'} | {row['name'] for row in mv_lock['external']}
    require(set(source_rows) == names and len(molten['sources']) == len(names), 'Missing/duplicate/unexpected MoltenVK sources')
    require(source_rows['MoltenVK']['url'] == mv_lock['url'] and
            source_rows['MoltenVK']['archive_sha256'] == mv_lock['sha256'], 'MoltenVK archive pin differs')
    for row in mv_lock['external']:
        actual = source_rows[row['name']]
        require(actual['url'] == row['url'] and actual['expected_git_sha1'] == row['revision']
                and actual['actual_git_sha1'].strip() == row['revision'], 'External Git pin differs: ' + row['name'])
    for name in ['cmake', 'ninja']:
        require(source_rows[name]['url'] == bootstrap[name]['url'] and
                source_rows[name]['archive_sha256'] == bootstrap[name]['sha256'], 'Bootstrap archive pin differs: ' + name)
    sources = []
    for row in molten['sources']:
        # Archive URLs and .git repository URLs have different shapes. Every
        # source above is compared to the exact official URL and archive/Git pin
        # in the already byte-sealed source recipe; do not broaden its allowlist.
        entry = dict(row, sha256=row['archive_sha256'])
        sources.append(entry)
    component = molten['components']['MoltenVK']
    require(component['version'] == mv_lock['version'] and component['state'] == 'BUILT'
            and component['source_built'] is True and component['input_sha256'] == mv_lock['sha256'],
            'MoltenVK component not accepted as stock build')
    require(component['selected_sha256'] == digest((molten_prefix / 'lib/libMoltenVK.dylib').read_bytes()),
            'Selected MoltenVK dylib drift')
    selected = {'lib/libMoltenVK.dylib', 'lib/pkgconfig/MoltenVK.pc'}
    copied, planned = [], []
    for row in molten['files']:
        name = row['path']
        if name in selected or name.startswith('include/MoltenVK/'):
            target = name
        elif name.startswith('share/licenses/'):
            target = 'share/licenses/MoltenVK-bundle/' + name[len('share/licenses/'):]
        else:
            continue
        source = molten_prefix / dep.safe_relative(name)
        destination = prefix / dep.safe_relative(target)
        require(not destination.exists() and not destination.is_symlink(), 'Output collision: ' + target)
        require(not source.is_symlink(), 'Selected MoltenVK output is a symlink: ' + name)
        planned.append((source, destination, name, target))
    for source, destination, name, target in planned:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied.append(dict(source=name, path=target, sha256=dep.file_sha(destination)))
    outputs = {row['path'] for row in copied}
    require(selected <= outputs and 'include/MoltenVK/vk_mvk_moltenvk.h' in outputs, 'Incomplete MoltenVK runtime/API import')
    normalized = dict(component, build_rc=0, sources=sources,
                      recipe_sha256=digest(mv_lock_raw + (REPO / 'repro109moltenvk/build_moltenvk.py').read_bytes()),
                      recipe_digest_format='SHA256(raw moltenvk.lock.json || raw build_moltenvk.py)',
                      licenses=[row['path'] for row in copied if row['path'].startswith('share/licenses/')],
                      original_manifest_sha256=digest(molten_raw), evidence='PRESENT_STOCK_NOT_INDIANA')
    require(normalized['licenses'], 'MoltenVK bundled source licenses missing')
    receipt = dict(base, components=dict(base['components'], MoltenVK=normalized), files=dep.inventory(prefix),
                   remaining_wine_required=[], status='WINE_SOURCE_DEPENDENCIES_COMPOSED_NOT_RUNTIME_ACCEPTED',
                   source_built=True, wine_ready=False,
                   original_manifest_sha256={'deps8': digest(deps_raw), 'moltenvk2': digest(molten_raw)})
    out.mkdir(parents=True, exist_ok=True)
    (out / 'deps8-original.json').write_bytes(deps_raw)
    (out / 'moltenvk2-original.json').write_bytes(molten_raw)
    path = out / 'dependency-manifest.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    # Use the actual consumer, including its file/closure validation.
    wine.dependencies(prefix, path, digest(path.read_bytes()))
    (out / 'composition.json').write_text(json.dumps(dict(schema=1, copied=copied,
        deps_manifest_sha256=digest(deps_raw), molten_manifest_sha256=digest(molten_raw),
        manifest_sha256=digest(path.read_bytes()), components=len(receipt['components']),
        prefix_preserved_in_place=True, runtime='NOT_ENABLED', indiana='NOT_ENABLED'), indent=2) + '\n')
    return path


def build(root, lock, jobs=4, profile='github'):
    cloud_guard(profile)  # Before work creation, source/tool execution or downloads.
    root = root.resolve()
    require(not root.exists(), 'Fresh cloud work required; no overwrite/retry')
    require(not any(char.isspace() for char in str(root)), 'Work path must not contain whitespace')
    root.mkdir(parents=True)
    out = root / 'reports'; out.mkdir()
    dep = load_driver('repro109_full_deps', REPO / 'repro109deps/build_deps.py')
    wine = load_driver('repro109_full_wine', HERE / 'build_wine.py')
    mv = load_driver('repro109_full_moltenvk', REPO / 'repro109moltenvk/build_moltenvk.py')
    deadline = time.monotonic() + lock['minutes'] * 60
    result = dict(schema=1, status='STARTED', comparison='NOT_ENABLED', stands='NOT_ENABLED',
                  signing='NOT_ENABLED', notarization='NOT_ENABLED', games='NOT_ENABLED', first_failure=None)
    phase = 'SDK_PREFLIGHT'
    def wine_command(argv, log, *, cwd=None, env=None, timeout=5400):
        # The existing bounded runner owns every compiler group directly. Do not
        # nest detached drivers whose descendants would outlive a killed parent.
        dep.command(argv, cwd or REPO, env, log, out, 'wine:' + log.name, deadline, timeout=timeout)
    try:
        if profile in ['github-macos15-arm64', 'github-xcode27-arm64']:
            selected = apply_profile(dep.read_lock(), profile)
            sdk, _, _ = dep.toolchain_preflight(selected['toolchain'], out)
            result['sdk_exports'] = check_sdk_exports(sdk, out)
        phase = 'DEPS10'
        dep.build(SimpleNamespace(work=root / 'deps', jobs=jobs, minutes=95), apply_profile(dep.read_lock(), profile))
        phase = 'MOLTENVK2'
        require(time.monotonic() < deadline, 'Task deadline before MoltenVK')
        mv.build(SimpleNamespace(work=root / 'moltenvk', jobs=jobs, minutes=60), apply_profile(mv.read_lock(), profile))
        phase = 'COMPOSITION'
        prefix = root / 'deps/prefix'
        manifest = compose(prefix, root / 'deps/reports/dependency-manifest.json', root / 'moltenvk/prefix',
                           root / 'moltenvk/reports/dependency-manifest.json', out / 'composition', dep, wine)
        phase = 'COMPILER_DOWNLOAD'
        compiler = root / 'llvm-mingw.tar.xz'
        require(time.monotonic() < deadline, 'Task deadline before compiler download')
        wine.download_compiler(lock['compiler'], compiler, out)
        phase = 'WINE'
        wine.command = wine_command
        wine.build(SimpleNamespace(work=root / 'wine', prefix=prefix, dependencies=manifest,
                   dependencies_sha256=digest(manifest.read_bytes()), llvm_mingw_archive=compiler, jobs=jobs), apply_profile(wine.inputs(), profile))
        built = json.loads((root / 'wine/reports/RESULT.json').read_bytes())
        require(built['status'] == 'FULL_WINE_BUILT_NOT_ACCEPTED' and built['install_skipped'] == 0,
                'Wine result not a complete source build')
        if profile == 'github-macos15-arm64':
            expected = json.loads((HERE / 'github-macos15.lock.json').read_bytes())['expected_standalone_wine']
            require(all(built[key] == value for key, value in expected.items()),
                    'Standalone Wine EC counts differ from source-built b43; review reports')
        result.update(status='FULL_WINE_SOURCE_BUILT_NOT_ACCEPTED', wine=built)
    except Exception as error:
        result.update(status='FAILED', first_failure=dict(phase=phase, error=str(error)))
        raise
    finally:
        result['install_skipped'] = sum('install skipped' in line.lower()
            for path in root.rglob('*.log') for line in path.read_text(errors='replace').splitlines())
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({key: result[key] for key in ['status', 'first_failure', 'install_skipped']}))


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-inputs', action='store_true')
    mode.add_argument('--build', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--profile', choices=['github', 'github-macos15-arm64', 'github-xcode27-arm64', 'xcode-cloud'], default='github-xcode27-arm64')
    args = parser.parse_args()
    lock = check_inputs()
    if args.check_inputs:
        print(json.dumps(dict(status='FULL_WINE_INPUTS_PINNED_NOT_BUILT', files=len(lock['files']))))
    else:
        require(args.work is not None and 1 <= args.jobs <= 8, 'Supply fresh work and 1..8 jobs')
        build(args.work, lock, args.jobs, args.profile)


if __name__ == '__main__':
    main()

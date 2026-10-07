#!/usr/bin/env python3
"""Source recipe for cloud macOS ARM64. No Vulkan instance/device/queue calls."""
import argparse
from functools import partial
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / 'repro109deps'))
sys.path.insert(0, str(REPO / 'repro109'))
import public_archive
from private_curl import source_transfer
OFFICIAL = {
    name: 'https://github.com/KhronosGroup/' + name + '.git'
    for name in ['SPIRV-Cross', 'SPIRV-Headers', 'SPIRV-Tools', 'Vulkan-Headers', 'Vulkan-Tools']
}
OFFICIAL['cereal'] = 'https://github.com/USCiLab/cereal.git'


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def require(condition, message, *, expected, actual):
    if not condition:
        values = {}
        for label, read in actual.items():
            try:
                values[label] = repr(read())[:600]
            except Exception as error:
                values[label] = "NOT_EVALUATED: " + type(error).__name__ + ": " + str(error)[:160]
        raise ValueError(str(message) + "; expected=" + expected + "; actual=" + repr(values))


def read_lock(path=HERE / 'moltenvk.lock.json'):
    lock = json.loads(path.read_text())
    require(lock['schema'] == 1 and lock['version'] == '1.4.1', 'Expected schema1/MoltenVK1.4.1', expected="lock['schema'] == 1 and lock['version'] == '1.4.1'", actual={"lock['schema']": lambda: lock['schema'], '1': lambda: 1, "lock['version']": lambda: lock['version'], "'1.4.1'": lambda: '1.4.1', 'lock': lambda: lock})
    require(lock['url'] == 'https://github.com/KhronosGroup/MoltenVK/archive/refs/tags/v1.4.1.tar.gz', 'Foreign MoltenVK source', expected="lock['url'] == 'https://github.com/KhronosGroup/MoltenVK/archive/refs/tags/v1.4.1.tar.gz'", actual={"lock['url']": lambda: lock['url'], "'https://github.com/KhronosGroup/MoltenVK/archive/refs/tags/v1.4.1.tar.gz'": lambda: 'https://github.com/KhronosGroup/MoltenVK/archive/refs/tags/v1.4.1.tar.gz', 'lock': lambda: lock})
    for key in ['sha256', 'shared_driver_sha256', 'shared_source_fixes_sha256', 'bootstrap_lock_sha256']:
        require(re.fullmatch('[0-9a-f]{64}', lock[key]) is not None, 'Invalid SHA256: ' + key, expected="re.fullmatch('[0-9a-f]{64}', lock[key]) is not None", actual={"re.fullmatch('[0-9a-f]{64}', lock[key])": lambda: re.fullmatch('[0-9a-f]{64}', lock[key]), 'None': lambda: None, 'lock[key]': lambda: lock[key], 'lock': lambda: lock, 'key': lambda: key})
    rows = lock['external']
    require(isinstance(rows, list) and len(rows) == len(OFFICIAL), 'Expected six External sources', expected='isinstance(rows, list) and len(rows) == len(OFFICIAL)', actual={'len(rows)': lambda: len(rows), 'len(OFFICIAL)': lambda: len(OFFICIAL), 'rows': lambda: rows, 'list': lambda: list, 'OFFICIAL': lambda: OFFICIAL})
    require({row['name'] for row in rows} == set(OFFICIAL), 'Missing/duplicate/foreign External source', expected="{row['name'] for row in rows} == set(OFFICIAL)", actual={"{row['name'] for row in rows}": lambda: {row['name'] for row in rows}, 'set(OFFICIAL)': lambda: set(OFFICIAL), "row['name']": lambda: row['name'], 'OFFICIAL': lambda: OFFICIAL, 'row': lambda: row, 'rows': lambda: rows})
    for row in rows:
        require(row['url'] == OFFICIAL[row['name']], 'Foreign External URL: ' + row['name'], expected="row['url'] == OFFICIAL[row['name']]", actual={"row['url']": lambda: row['url'], "OFFICIAL[row['name']]": lambda: OFFICIAL[row['name']], 'row': lambda: row, 'OFFICIAL': lambda: OFFICIAL, "row['name']": lambda: row['name']})
        require(re.fullmatch('[0-9a-f]{40}', row['revision']) is not None, 'Invalid Git commit OID', expected="re.fullmatch('[0-9a-f]{40}', row['revision']) is not None", actual={"re.fullmatch('[0-9a-f]{40}', row['revision'])": lambda: re.fullmatch('[0-9a-f]{40}', row['revision']), 'None': lambda: None, "row['revision']": lambda: row['revision'], 'row': lambda: row})
    for key, path in [('shared_driver_sha256', REPO / 'repro109deps/build_deps.py'),
                      ('shared_source_fixes_sha256', REPO / 'repro109deps/source_fixes.py'),
                      ('bootstrap_lock_sha256', REPO / 'repro109deps/deps.lock.json')]:
        require(sha(path) == lock[key], 'Shared recipe drift: ' + key, expected='sha(path) == lock[key]', actual={'sha(path)': lambda: sha(path), 'lock[key]': lambda: lock[key], 'path': lambda: path, 'lock': lambda: lock, 'key': lambda: key})
    bootstrap = json.loads((REPO / 'repro109deps/deps.lock.json').read_text())
    require(lock['toolchain'] == bootstrap['toolchain'], 'Bootstrap toolchain drift', expected="lock['toolchain'] == bootstrap['toolchain']", actual={"lock['toolchain']": lambda: lock['toolchain'], "bootstrap['toolchain']": lambda: bootstrap['toolchain'], 'lock': lambda: lock, 'bootstrap': lambda: bootstrap})
    return lock


def shared_driver():
    spec = importlib.util.spec_from_file_location('repro109_shared_deps', REPO / 'repro109deps/build_deps.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Only this official project is added; the shared file/47 recipes stay byte-exact.
    module.GITHUB_PROJECTS = {*module.GITHUB_PROJECTS, 'KhronosGroup/MoltenVK'}
    return module


def download_moltenvk(lock, destination, out):
    # This source is outside the fixed dependency-component routes.
    if lock['url'] != 'https://github.com/KhronosGroup/MoltenVK/archive/refs/tags/v1.4.1.tar.gz':
        raise ValueError('Foreign MoltenVK source refused')
    row = dict(name='moltenvk', url=lock['url'], sha256=lock['sha256'], maximum_size=256 * 1024**2)
    return public_archive.download(row, destination, out,
        transfer=partial(source_transfer, allowed_hosts=['github.com', 'codeload.github.com']))


def cloud_guard():
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Expected native cloud macOS ARM64', expected="platform.system() == 'Darwin' and platform.machine() == 'arm64'", actual={'platform.system()': lambda: platform.system(), "'Darwin'": lambda: 'Darwin', 'platform.machine()': lambda: platform.machine(), "'arm64'": lambda: 'arm64'})
    require(os.environ.get('GITHUB_ACTIONS') == 'true' or os.environ.get('CI_XCODE_CLOUD') == 'TRUE'
            or (os.environ.get('CI_WORKSPACE_PATH') and os.environ.get('CI_PRIMARY_REPOSITORY_PATH')),
            'Build/download enabled only inside an agreed cloud task', expected="os.environ.get('GITHUB_ACTIONS') == 'true' or os.environ.get('CI_XCODE_CLOUD') == 'TRUE'", actual={"os.environ.get('GITHUB_ACTIONS')": lambda: os.environ.get('GITHUB_ACTIONS'), "'true'": lambda: 'true', "os.environ.get('CI_XCODE_CLOUD')": lambda: os.environ.get('CI_XCODE_CLOUD'), "'TRUE'": lambda: 'TRUE'})
    # Source/tool pins are repository-independent. Private release checks stay
    # in the caller's publishing job; a user's cloud build needs no private API.


def verify_external_revisions(source, lock):
    result = []
    for row in lock['external']:
        relative = 'ExternalRevisions/' + row['name'] + '_repo_revision'
        path = source / relative
        actual = path.read_text().strip()
        require(actual == row['revision'], f'External revision mismatch: {relative}: expected={row["revision"]} actual={actual}', expected="actual == row['revision']", actual={'actual': lambda: actual, "row['revision']": lambda: row['revision'], 'row': lambda: row})
        result.append(dict(path=relative, sha256=sha(path), expected=row['revision'], actual=actual))
    return result


def verify_git_revision(expected, actual):
    require(actual == expected, f'Git HEAD mismatch: expected={expected} actual={actual}', expected='actual == expected', actual={'actual': lambda: actual, 'expected': lambda: expected})


def verify_xcode_source(text, source):
    paths = re.findall(r'^\s*(?:SRCROOT|PROJECT_DIR) = (.+)$', text, re.M)
    require(bool(paths), 'No Xcode source roots in build settings', expected='bool(paths)', actual={'paths': lambda: paths})
    root = source.resolve()
    for value in paths:
        require(Path(value.strip()).resolve().is_relative_to(root), 'Foreign Xcode source root: ' + value, expected='Path(value.strip()).resolve().is_relative_to(root)', actual={'root': lambda: root, 'value': lambda: value})
    return dict(state='PRESENT', inspected=len(paths), foreign=0)


def verify_dylib(path):
    with path.open('rb') as stream:
        header = stream.read(32)
    require(len(header) == 32, 'Truncated MoltenVK Mach-O header', expected='len(header) == 32', actual={'len(header)': lambda: len(header), '32': lambda: 32, 'header': lambda: header})
    magic, cpu, subtype, kind = struct.unpack('<IIII', header[:16])
    require((magic, cpu, kind) == (0xfeedfacf, 0x100000c, 6),
            f'Expected thin ARM64 MH_DYLIB: actual={magic:#x}/{cpu:#x}/{kind}', expected='(magic, cpu, kind) == (4277009103, 16777228, 6)', actual={'(magic, cpu, kind)': lambda: (magic, cpu, kind), '(4277009103, 16777228, 6)': lambda: (4277009103, 16777228, 6), 'magic': lambda: magic, 'cpu': lambda: cpu, 'kind': lambda: kind})
    return dict(state='PRESENT', cpu=cpu, subtype=subtype, filetype=kind)


def xcode_args(source, project, scheme, prefix, sdk, jobs):
    # These are the paths consumed by the pinned upstream packaging projects.
    build = source / ('External/build' if project.startswith('External') else 'build')
    return ['xcodebuild', '-project', project, '-scheme', scheme, '-configuration', 'Release',
            '-destination', 'generic/platform=macOS', '-derivedDataPath', str(build), '-jobs', str(jobs),
            'ARCHS=arm64', 'ONLY_ACTIVE_ARCH=YES', 'CODE_SIGNING_ALLOWED=NO', 'CODE_SIGNING_REQUIRED=NO',
            'MACOSX_DEPLOYMENT_TARGET=14.0', 'SDKROOT=' + str(sdk), 'SYMROOT=' + str(build), 'OBJROOT=' + str(build),
            'GCC_PREPROCESSOR_DEFINITIONS=$(inherited) MVK_CONFIG_LOG_LEVEL=MVK_CONFIG_LOG_LEVEL_NONE']


def build(args, lock):
    # The guard precedes work-directory creation, tool execution and every network call.
    cloud_guard()
    if lock['toolchain'].get('profile') == 'xcode-cloud':
        if tuple(sys.version_info[:2]) < tuple(lock['toolchain']['python_minimum']):
            raise ValueError('Xcode Cloud MoltenVK requires selected Apple Python >=3.9')
    else:
        require(platform.python_version() == lock['toolchain']['python'], 'Python version differs from lock', expected="platform.python_version() == lock['toolchain']['python']", actual={'platform.python_version()': lambda: platform.python_version(), "lock['toolchain']['python']": lambda: lock['toolchain']['python'], "lock['toolchain']": lambda: lock['toolchain'], 'lock': lambda: lock})
    require(not args.work.exists(), 'Work directory already exists; no overwrite/retry', expected='not args.work.exists()', actual={'args': lambda: args})
    dep = shared_driver()
    root = args.work.resolve()
    root.mkdir(parents=True)
    out, prefix = root / 'reports', root / 'prefix'
    out.mkdir(); prefix.mkdir()
    archives = root / 'archives'; archives.mkdir()
    sources = root / 'sources'; sources.mkdir()
    deadline = time.monotonic() + args.minutes * 60
    receipt = dict(schema=1, status='STARTED', source_built=False, scope=lock['scope'],
                   lock_sha256=sha(HERE / 'moltenvk.lock.json'), sources=[], components={},
                   first_failure=None, wine_ready=False, comparison='NOT_ENABLED', stands='NOT_ENABLED',
                   gpu_execution='NOT_ENABLED', signature='NOT_ENABLED', notarization='NOT_ENABLED')
    phase, current = 'TOOLCHAIN', 'toolchain'

    def run(argv, cwd, name, timeout=1800):
        require(time.monotonic() < deadline, 'Task deadline exceeded before command', expected='time.monotonic() < deadline', actual={'time.monotonic()': lambda: time.monotonic(), 'deadline': lambda: deadline})
        dep.command(argv, cwd, env, out / (name + '.log'), out, current, deadline, timeout=timeout)

    try:
        sdk, clang, clangxx = dep.toolchain_preflight(lock['toolchain'], out)
        (out / 'effective-build.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
        env = dep.environment(prefix, lock['toolchain'], clang, clangxx, sdk)
        env.update(GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
        bootstrap = dep.read_lock()
        # Exactly the already accepted source recipes for two tools, no installed brew tools.
        for current in ['cmake', 'ninja']:
            row = next(row for row in bootstrap['components'] if row['name'] == current)
            phase = 'BOOTSTRAP_DOWNLOAD'
            require(time.monotonic() < deadline, 'Task deadline exceeded before download', expected='time.monotonic() < deadline', actual={'time.monotonic()': lambda: time.monotonic(), 'deadline': lambda: deadline})
            archive = archives / (current + '.tar.gz')
            dep.download(row, archive, out)
            source = dep.unpack(archive, sources / current)
            phase = 'BOOTSTRAP_BUILD'
            for number, argv in enumerate(dep.build_steps(row, source, prefix, sdk, args.jobs, (clang, clangxx)), 1):
                run(argv, source, current + '-' + str(number))
            if current == 'ninja':
                (prefix / 'bin').mkdir(exist_ok=True)
                shutil.copy2(source / 'ninja', prefix / 'bin/ninja')
            version = dep.output([str(prefix / 'bin' / current), '--version'], env, out / (current + '-version.log'))
            require(version.splitlines()[0] == ('cmake version ' if current == 'cmake' else '') + row['version'], 'Bootstrap version mismatch', expected="version.splitlines()[0] == ('cmake version ' if current == 'cmake' else '') + row['version']", actual={'version.splitlines()[0]': lambda: version.splitlines()[0], "('cmake version ' if current == 'cmake' else '') + row['version']": lambda: ('cmake version ' if current == 'cmake' else '') + row['version'], "row['version']": lambda: row['version'], 'current': lambda: current, "'cmake'": lambda: 'cmake', 'row': lambda: row, 'version': lambda: version})
            receipt['sources'].append(dict(name=current, archive_sha256=sha(archive), url=row['url']))
            dep.licenses(source, prefix, current)
        current, phase = 'MoltenVK', 'SOURCE_DOWNLOAD'
        archive = archives / 'MoltenVK-1.4.1.tar.gz'
        require(time.monotonic() < deadline, 'Task deadline exceeded before download', expected='time.monotonic() < deadline', actual={'time.monotonic()': lambda: time.monotonic(), 'deadline': lambda: deadline})
        download_moltenvk(lock, archive, out)
        source = dep.unpack(archive, sources / 'MoltenVK')
        receipt['external_revision_files'] = verify_external_revisions(source, lock)
        receipt['sources'].append(dict(name=current, archive_sha256=sha(archive), url=lock['url']))
        external = source / 'External'; external.mkdir(exist_ok=True)
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never']
        for row in lock['external']:
            current, phase = row['name'], 'EXTERNAL_SOURCE'
            destination = external / current
            destination.mkdir()
            run([*git, 'init', '--quiet', str(destination)], source, current + '-git-init')
            run([*git, '-C', str(destination), 'fetch', '--depth=1', '--no-tags', row['url'], row['revision']], source, current + '-git-fetch', timeout=600)
            actual = dep.output([*git, '-C', str(destination), 'rev-parse', 'FETCH_HEAD'], env, out / (current + '-commit.log'))
            verify_git_revision(row['revision'], actual)
            run([*git, '-C', str(destination), 'fsck', '--strict', '--no-reflogs'], source, current + '-git-fsck')
            run([*git, '-C', str(destination), 'checkout', '--detach', row['revision']], source, current + '-git-checkout')
            raw_tree = dep.output([*git, '-C', str(destination), 'ls-tree', '-r', 'HEAD'], env, out / (current + '-git-tree.log'))
            require(not any(line.startswith('160000 ') for line in raw_tree.splitlines()), 'Unpinned Git submodule', expected="not any((line.startswith('160000 ') for line in raw_tree.splitlines()))", actual={'raw_tree': lambda: raw_tree})
            snapshot = archives / (current + '.tar')
            run([*git, '-C', str(destination), 'archive', '--format=tar', '--prefix=' + current + '/', '--output=' + str(snapshot), 'HEAD'], source, current + '-git-archive')
            receipt['sources'].append(dict(name=current, url=row['url'], expected_git_sha1=row['revision'], actual_git_sha1=actual,
                                          archive_sha256=sha(snapshot), archive_sha256_state='MEASURED_IN_CLOUD_NOT_PREPINNED'))
            dep.licenses(destination, prefix, current)
        current, phase = 'MoltenVK', 'SPIRV_HEADERS_STAGING'
        tools = external / 'SPIRV-Tools'
        headers = tools / 'external/spirv-headers'
        require(not headers.exists(), 'Unexpected preexisting SPIRV-Headers input', expected='not headers.exists()', actual={'headers': lambda: headers})
        shutil.copytree(external / 'SPIRV-Headers', headers, ignore=shutil.ignore_patterns('.git'))
        phase = 'SPIRV_TOOLS_BUILD'
        cmake = str(prefix / 'bin/cmake')
        tools_build = tools / '_repro_build'
        argv = [cmake, '-S', str(tools), '-B', str(tools_build), '-G', 'Ninja',
                '-DCMAKE_MAKE_PROGRAM=' + str(prefix / 'bin/ninja'), '-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_C_COMPILER=' + clang, '-DCMAKE_CXX_COMPILER=' + clangxx,
                '-DCMAKE_OSX_SYSROOT=' + str(sdk), '-DCMAKE_OSX_ARCHITECTURES=arm64',
                '-DCMAKE_OSX_DEPLOYMENT_TARGET=14.0', '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
                '-DSPIRV_SKIP_TESTS=ON', '-DSPIRV_SKIP_EXECUTABLES=ON']
        run(argv, source, 'spirv-tools-configure')
        cache = (tools_build / 'CMakeCache.txt').read_text()
        home = re.search(r'^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$', cache, re.M)
        require(home is not None and Path(home[1]).resolve() == tools.resolve(), 'Foreign CMake source', expected='home is not None and Path(home[1]).resolve() == tools.resolve()', actual={'home': lambda: home, 'None': lambda: None, 'Path(home[1]).resolve()': lambda: Path(home[1]).resolve(), 'tools.resolve()': lambda: tools.resolve(), 'tools': lambda: tools, 'home[1]': lambda: home[1]})
        # The Xcode project consumes generated includes from External/SPIRV-Tools/build.
        run([cmake, '--build', str(tools_build), '--parallel', str(args.jobs)], source, 'spirv-tools-build')
        shutil.copytree(tools_build, tools / 'build')
        receipt['cmake_source_ownership'] = dict(state='PRESENT', expected=str(tools.resolve()), actual=home[1])
        phase = 'XCODE_BUILD'
        for project, scheme, name in [('ExternalDependencies.xcodeproj', 'ExternalDependencies-macOS', 'external'),
                                      ('MoltenVKPackaging.xcodeproj', 'MoltenVK Package (macOS only)', 'moltenvk')]:
            base = xcode_args(source, project, scheme, prefix, sdk, args.jobs)
            run([*base, '-showBuildSettings'], source, name + '-settings', timeout=120)
            settings = (out / (name + '-settings.log')).read_text()
            receipt[name + '_source_ownership'] = verify_xcode_source(settings, source)
            run([*base, 'build'], source, name + '-build')
        phase = 'INSTALL'
        library = source / 'Package/Release/MoltenVK/dylib/macOS/libMoltenVK.dylib'
        require(library.is_file(), 'Expected package output missing: Package/Release/MoltenVK/dylib/macOS/libMoltenVK.dylib', expected='library.is_file()', actual={'library': lambda: library})
        receipt['macho'] = verify_dylib(library)
        (prefix / 'lib').mkdir(exist_ok=True)
        selected = prefix / 'lib/libMoltenVK.dylib'
        shutil.copy2(library, selected)
        receipt['original_dylib_sha256'] = sha(library)
        run(['xcrun', 'install_name_tool', '-id', '@rpath/libMoltenVK.dylib', str(selected)], source, 'install-name')
        verify_dylib(selected)
        links = dep.output(['xcrun', 'otool', '-L', str(selected)], env, out / 'dylib-links.log')
        require('/opt/homebrew/' not in links and '/usr/local/' not in links, 'Foreign dynamic library dependency', expected="'/opt/homebrew/' not in links and '/usr/local/' not in links", actual={"'/opt/homebrew/'": lambda: '/opt/homebrew/', 'links': lambda: links, "'/usr/local/'": lambda: '/usr/local/'})
        shutil.copytree(source / 'MoltenVK/MoltenVK/API', prefix / 'include/MoltenVK')
        pc = prefix / 'lib/pkgconfig/MoltenVK.pc'; pc.parent.mkdir(exist_ok=True)
        pc.write_text('prefix=${pcfiledir}/../..\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\n\n'
                      'Name: MoltenVK\nDescription: Source-built stock Wine dependency\nVersion: 1.4.1\n'
                      'Libs: -L${libdir} -lMoltenVK\nCflags: -I${includedir}\n')
        dep.licenses(source, prefix, 'MoltenVK')
        receipt['files'] = dep.inventory(prefix)
        receipt['components']['MoltenVK'] = dict(version=lock['version'], state='BUILT', source_built=True,
            selected_sha256=sha(selected), input_sha256=lock['sha256'], external_sources=len(lock['external']),
            outputs=['lib/libMoltenVK.dylib', 'lib/pkgconfig/MoltenVK.pc', 'include/MoltenVK/vk_mvk_moltenvk.h'])
        receipt.update(status='MOLTENVK_SOURCE_BUILT_NOT_INDIANA_ACCEPTANCE', source_built=True)
    except Exception as error:
        receipt.update(status='FAILED', first_failure=dict(component=current, phase=phase, error=str(error)))
        raise
    finally:
        skipped = sum('install skipped' in line.lower() for path in out.glob('*.log')
                      for line in path.read_text(errors='replace').splitlines())
        receipt['install_skipped'] = skipped
        if skipped:
            receipt.update(status='FAILED', source_built=False)
            if receipt['first_failure'] is None:
                receipt['first_failure'] = dict(component=current, phase='INSTALL', error='install skipped=' + str(skipped))
        (out / 'dependency-manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
        (out / 'RESULT.json').write_text(json.dumps({key: receipt[key] for key in
            ['status', 'source_built', 'first_failure', 'wine_ready', 'comparison', 'stands', 'gpu_execution', 'install_skipped']}, indent=2) + '\n')
    require(receipt['status'] != 'FAILED', 'MoltenVK source build failed', expected="receipt['status'] != 'FAILED'", actual={"receipt['status']": lambda: receipt['status'], "'FAILED'": lambda: 'FAILED', 'receipt': lambda: receipt})
    print(json.dumps(dict(status=receipt['status'], external_sources=len(lock['external']), gpu_execution='NOT_ENABLED')))


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-inputs', action='store_true'); mode.add_argument('--build', action='store_true')
    parser.add_argument('--work', type=Path); parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--minutes', type=int, default=90)
    args = parser.parse_args(); lock = read_lock()
    if args.check_inputs:
        print(json.dumps(dict(status='INPUTS_OK_NOT_BUILT', external_sources=len(lock['external']))))
    else:
        require(args.work is not None and 1 <= args.jobs <= 8 and 1 <= args.minutes <= 90, 'Invalid build bounds', expected='args.work is not None and 1 <= args.jobs <= 8 and (1 <= args.minutes <= 90)', actual={'args.work': lambda: args.work, 'None': lambda: None, '1': lambda: 1, 'args.jobs': lambda: args.jobs, '8': lambda: 8, 'args.minutes': lambda: args.minutes, '90': lambda: 90, 'args': lambda: args})
        build(args, lock)


if __name__ == '__main__':
    main()

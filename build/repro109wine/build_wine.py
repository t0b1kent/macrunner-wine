#!/usr/bin/env python3
"""Fresh full Wine build. Source inputs check is safe/offline; build uses a pinned dependency prefix."""
import argparse
import importlib.util
import hashlib
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

RECIPE = Path(__file__).resolve().parent
sys.path.insert(0, str(RECIPE.parent / 'repro109'))
import archive_safety
import public_archive
sys.path.insert(0, str(RECIPE.parent / 'repro109deps'))
import build_deps as dependency_driver

COMPILER_URL = ('https://github.com/mstorsjo/llvm-mingw/releases/download/20260505/'
                'llvm-mingw-20260505-ucrt-macos-universal.tar.xz')
late_spec = importlib.util.spec_from_file_location('repro109_wine_late_source', RECIPE / 'late_source.py')
late_source = importlib.util.module_from_spec(late_spec)
late_spec.loader.exec_module(late_source)


def _check_message(expected, actual, note=''):
    def bounded(value):
        if isinstance(value, bytes):
            return 'bytes=' + str(len(value)) + '; prefix_hex=' + value[:32].hex()
        return repr(value)[:600]
    return str(note) + '; expected=' + expected + '; actual=' + repr(
        {key: bounded(value) for key, value in actual.items()})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def relative(name):
    path = Path(name)
    if not (not (_repro_check_0_0 := path.is_absolute()) and (_repro_check_0_1 := '..') not in (_repro_check_0_2 := path.parts)):
        raise AssertionError(_check_message("not path.is_absolute() and '..' not in path.parts", {'path.is_absolute()': locals().get('_repro_check_0_0', 'NOT_EVALUATED'), "'..'": locals().get('_repro_check_0_1', 'NOT_EVALUATED'), 'path.parts': locals().get('_repro_check_0_2', 'NOT_EVALUATED')}, 'Unsafe manifest path'))
    return path


def inputs():
    lock = json.loads((RECIPE / 'wine.lock.json').read_text())
    if (lock['schema'] != 2 or lock['overlay'] != [] or
            lock['revision'] != 'ce9f9ed6177d57a43f6fd1e9c8d9be87224eb08a' or
            lock['repository'] != 'https://github.com/t0b1kent/macrunner-wine.git'):
        raise ValueError('Pinned public Wine 1.0.8 base without overlays required')
    required = {x['path']: x['git_blob'] for x in lock['required_base_files']}
    released = lock['base_release_sources']
    if (len(required) != 797 or len(lock['required_base_files']) != 797 or
            len(released) != 20 or len({x['path'] for x in released}) != 20 or
            lock['base_release_source_count'] != 20):
        raise ValueError('Wine public base source count/uniqueness differs')
    for row in released:
        relative(row['path'])
        if (required.get(row['path']) != row['git_blob'] or type(row['bytes']) is not int or
                row['bytes'] <= 0 or not re.fullmatch('[0-9a-f]{64}', row['sha256'])):
            raise ValueError('Wine public release source pin differs')
    for row in lock['overlay']:
        data = (RECIPE / 'source' / relative(row['path'])).read_bytes()
        if not ((_repro_check_4_0 := len(data)) == (_repro_check_4_1 := row['bytes']) and (_repro_check_4_2 := sha(data)) == (_repro_check_4_3 := row['sha256'])):
            raise AssertionError(_check_message("len(data) == row['bytes'] and sha(data) == row['sha256']", {'len(data)': locals().get('_repro_check_4_0', 'NOT_EVALUATED'), "row['bytes']": locals().get('_repro_check_4_1', 'NOT_EVALUATED'), 'sha(data)': locals().get('_repro_check_4_2', 'NOT_EVALUATED'), "row['sha256']": locals().get('_repro_check_4_3', 'NOT_EVALUATED')}, row['path']))
    late = late_source.inputs()
    if late['wine_revision'] != lock['revision']:
        raise ValueError('Wine base and required keyboard source revision differ')
    return lock


def check_release_sources(source, lock):
    rows = []
    for row in lock['base_release_sources']:
        path = source / relative(row['path'])
        if path.is_symlink() or not path.is_file():
            raise ValueError('Wine public release source missing/symlink: ' + row['path'])
        data = path.read_bytes()
        if len(data) != row['bytes'] or sha(data) != row['sha256'] or blob(data) != row['git_blob']:
            raise ValueError('Wine public release source bytes differ: ' + row['path'])
        rows.append(dict(path=row['path'], bytes=len(data), sha256=sha(data)))
    return dict(state='PRESENT', files=len(rows), overlay_files=0, sources=rows)


def prepare_loader_game_mode(source, reports):
    """Put the accepted Game Mode keys in Wine's embedded plist before linking.

    The loader itself is compiled by the existing full Wine build. No historical
    executable, signed bundle, provisioning profile or signing identity is used.
    """
    target = source / 'loader/wine_info.plist.in'
    if target.is_symlink() or not target.is_file():
        raise ValueError('Wine loader plist source must be an ordinary file')
    before = target.read_bytes()
    expected = '222e2ea91b09c6130172b3f4200aaf2ed145d7001396a763ab1d43a784c1b4bd'
    if len(before) != 1054 or sha(before) != expected:
        raise ValueError('Pinned public Wine loader plist source drift')
    keys = dict(GCSupportsGameMode=True, LSSupportsGameMode=True,
                LSApplicationCategoryType='public.app-category.games')
    document = plistlib.loads(before)
    if document.get('CFBundleIdentifier') != 'app.macrunner.wineloader':
        raise ValueError('Wine loader bundle identifier drift')
    addition = (b'    <key>GCSupportsGameMode</key>\n    <true/>\n'
                b'    <key>LSSupportsGameMode</key>\n    <true/>\n'
                b'    <key>LSApplicationCategoryType</key>\n'
                b'    <string>public.app-category.games</string>\n')
    if before.count(b'</dict>') != 1:
        raise ValueError('Wine loader plist dictionary count differs')
    after = before.replace(b'</dict>', addition + b'</dict>')
    if plistlib.loads(after) != dict(document, **keys):
        raise ValueError('Wine loader Game Mode source transformation differs')
    target.write_bytes(after)
    record = dict(status='LOADER_GAME_MODE_SOURCE_PREPARED_NOT_LINKED',
                  wine_revision='ce9f9ed6177d57a43f6fd1e9c8d9be87224eb08a',
                  path='loader/wine_info.plist.in', before_bytes=len(before),
                  before_sha256=sha(before), after_bytes=len(after),
                  after_sha256=sha(after), game_mode_keys=keys,
                  signing='NOT_ENABLED', notarization='NOT_ENABLED',
                  embedded_output='NOT_CAPTURED', external_bundle='NOT_ASSEMBLED')
    (reports / 'loader-game-mode-source.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def source_headers(source):
    """Inventory source headers only; generated headers are not present yet."""
    include = Path(source) / 'include'
    if not include.is_dir() or include.is_symlink():
        raise ValueError('Wine include source directory required')
    result = set()
    for path in include.rglob('*.h'):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Wine source header must be regular: ' + str(path.relative_to(source)))
        result.add(path.relative_to(source).as_posix())
    return result


def check_header_sources(source, lock, out=None, baseline=None):
    """Check added include headers against the real makedep SOURCES list.

    Existing unlisted headers are reported separately, not granted to new files.
    arm64_memmove is checked even after it becomes part of the public base.
    """
    source = Path(source)
    headers = source_headers(source)
    if baseline is None:
        baseline = {row['path'] for row in lock['required_base_files']
                    if row['path'].startswith('include/') and row['path'].endswith('.h')}
    baseline = set(baseline)
    required = headers - baseline
    required.update(row['path'] for row in lock['overlay']
                    if row['path'].startswith('include/') and row['path'].endswith('.h'))
    if 'include/wine/arm64_memmove.h' in headers:
        required.add('include/wine/arm64_memmove.h')
    makefile = source / 'include/Makefile.in'
    if makefile.is_symlink() or not makefile.is_file():
        raise ValueError('Wine include/Makefile.in source required')
    raw = makefile.read_bytes()
    logical, pending = [], ''
    for line in raw.decode('utf-8').splitlines():
        line = line.split('#', 1)[0].rstrip()
        if line.endswith('\\'):
            pending += line[:-1] + ' '
        else:
            logical.append(pending + line)
            pending = ''
    if pending:
        raise ValueError('Unterminated Wine include SOURCES continuation')
    declarations = [re.fullmatch(r'\s*SOURCES\s*([:+?]?=)\s*(.*?)\s*', line)
                    for line in logical if re.match(r'\s*SOURCES\s*[:+?]?=', line)]
    if len(declarations) != 1 or declarations[0] is None or declarations[0][1] != '=':
        raise ValueError('Expected one literal Wine include SOURCES = declaration')
    names = declarations[0][2].split()
    if any(re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None for name in names):
        raise ValueError('Nonliteral Wine include SOURCES entry')
    registered = {'include/' + name for name in names}
    missing = sorted(required - registered)
    absent = sorted(required - headers)
    receipt = dict(status='FAILED' if missing or absent else 'PRESENT',
                   source_headers=len(headers), baseline_headers=len(baseline),
                   sources_entries=len(names), required_headers=sorted(required),
                   missing_sources=missing, absent_headers=absent,
                   legacy_unlisted_headers=sorted((headers & baseline) - registered - required),
                   makefile_sha256=sha(raw),
                   header_sha256={name: sha((source / name).read_bytes())
                                  for name in sorted(required & headers)})
    if out is not None:
        with (Path(out) / 'header-sources.json').open('x') as stream:
            stream.write(json.dumps(receipt, indent=2) + '\n')
    if missing or absent:
        raise ValueError('Wine include SOURCES missing=' + repr(missing) + '; absent headers=' + repr(absent))
    return receipt


def dependencies(prefix, manifest, expected):
    """Verify the explicitly sealed source-built prefix; never run brew bootstrap."""
    if not ((_repro_check_5_0 := re.fullmatch('[0-9a-f]{64}', expected))):
        raise AssertionError(_check_message("re.fullmatch('[0-9a-f]{64}', expected)", {"re.fullmatch('[0-9a-f]{64}', expected)": locals().get('_repro_check_5_0', 'NOT_EVALUATED')}, 'An exact dependency manifest SHA is required'))
    data = manifest.read_bytes()
    if not ((_repro_check_6_0 := sha(data)) == (_repro_check_6_1 := expected)):
        raise AssertionError(_check_message('sha(data) == expected', {'sha(data)': locals().get('_repro_check_6_0', 'NOT_EVALUATED'), 'expected': locals().get('_repro_check_6_1', 'NOT_EVALUATED')}, 'Dependency manifest drift'))
    receipt = json.loads(data)
    if not ((_repro_check_7_0 := receipt['schema']) == (_repro_check_7_1 := 1) and (_repro_check_7_2 := receipt['source_built']) is (_repro_check_7_3 := True)):
        raise AssertionError(_check_message("receipt['schema'] == 1 and receipt['source_built'] is True", {"receipt['schema']": locals().get('_repro_check_7_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_7_1', 'NOT_EVALUATED'), "receipt['source_built']": locals().get('_repro_check_7_2', 'NOT_EVALUATED'), 'True': locals().get('_repro_check_7_3', 'NOT_EVALUATED')}, 'validation failed'))
    components = receipt['components']
    required = {'bison', 'flex', 'pkgconf', 'gettext', 'glib', 'gstreamer',
                'gst-plugins-base', 'ffmpeg', 'freetype', 'fontconfig', 'libpng',
                'gnutls', 'libusb', 'sdl2', 'MoltenVK', 'Vulkan-Headers'}
    if not ((_repro_check_8_0 := required) <= (_repro_check_8_1 := set(components))):
        raise AssertionError(_check_message('required <= set(components)', {'required': locals().get('_repro_check_8_0', 'NOT_EVALUATED'), 'set(components)': locals().get('_repro_check_8_1', 'NOT_EVALUATED')}, 'Incomplete Wine dependency closure'))
    for name, component in components.items():
        if not ((_repro_check_9_0 := component['version']) and (_repro_check_9_1 := component['recipe_sha256']) and ((_repro_check_9_2 := component['build_rc']) == (_repro_check_9_3 := 0))):
            raise AssertionError(_check_message("component['version'] and component['recipe_sha256'] and component['build_rc'] == 0", {"component['version']": locals().get('_repro_check_9_0', 'NOT_EVALUATED'), "component['recipe_sha256']": locals().get('_repro_check_9_1', 'NOT_EVALUATED'), "component['build_rc']": locals().get('_repro_check_9_2', 'NOT_EVALUATED'), '0': locals().get('_repro_check_9_3', 'NOT_EVALUATED')}, name))
        if not ((_repro_check_10_0 := re.fullmatch('[0-9a-f]{64}', component['recipe_sha256']))):
            raise AssertionError(_check_message("re.fullmatch('[0-9a-f]{64}', component['recipe_sha256'])", {"re.fullmatch('[0-9a-f]{64}', component['recipe_sha256'])": locals().get('_repro_check_10_0', 'NOT_EVALUATED')}, name))
        sources = component['sources']
        if not ((_repro_check_11_0 := sources)):
            raise AssertionError(_check_message('sources', {'sources': locals().get('_repro_check_11_0', 'NOT_EVALUATED')}, name))
        for source in sources:
            if not ((_repro_check_12_0 := source['url'].startswith('https://'))):
                raise AssertionError(_check_message("source['url'].startswith('https://')", {"source['url'].startswith('https://')": locals().get('_repro_check_12_0', 'NOT_EVALUATED')}, name))
            if not ((_repro_check_13_0 := re.fullmatch('[0-9a-f]{64}', source['sha256']))):
                raise AssertionError(_check_message("re.fullmatch('[0-9a-f]{64}', source['sha256'])", {"re.fullmatch('[0-9a-f]{64}', source['sha256'])": locals().get('_repro_check_13_0', 'NOT_EVALUATED')}, name))
    if not ((_repro_check_14_0 := receipt['files'])):
        raise AssertionError(_check_message("receipt['files']", {"receipt['files']": locals().get('_repro_check_14_0', 'NOT_EVALUATED')}, 'Empty dependency prefix receipt'))
    for row in receipt['files']:
        path = prefix / relative(row['path'])
        if not ((_repro_check_15_0 := path.resolve().is_relative_to(prefix.resolve()))):
            raise AssertionError(_check_message('path.resolve().is_relative_to(prefix.resolve())', {'path.resolve().is_relative_to(prefix.resolve())': locals().get('_repro_check_15_0', 'NOT_EVALUATED')}, 'Dependency symlink leaves prefix'))
        if not ((_repro_check_16_0 := sha(path.read_bytes())) == (_repro_check_16_1 := row['sha256'])):
            raise AssertionError(_check_message("sha(path.read_bytes()) == row['sha256']", {'sha(path.read_bytes())': locals().get('_repro_check_16_0', 'NOT_EVALUATED'), "row['sha256']": locals().get('_repro_check_16_1', 'NOT_EVALUATED')}, row['path']))
    return receipt


def command(argv, log, *, cwd=None, env=None, timeout=5400):
    with log.open('ab') as stream:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if not ((_repro_check_17_0 := result.returncode) == (_repro_check_17_1 := 0)):
        raise AssertionError(_check_message('result.returncode == 0', {'result.returncode': locals().get('_repro_check_17_0', 'NOT_EVALUATED'), '0': locals().get('_repro_check_17_1', 'NOT_EVALUATED')}, f'{log.name}: exit {result.returncode}'))


def text(argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT).strip()


def download_compiler(row, destination, out):
    # llvm-mingw is a tool archive, outside the 46 component source routes.
    if row['name'] != 'llvm-mingw' or row['url'] != COMPILER_URL:
        raise ValueError('Foreign llvm-mingw publisher/version refused')
    return public_archive.download(row, destination, out)


def prepare_compiler(archive, destination, expected_sha256, out):
    """Verify and unpack without executing any downloaded tool, also on Apple Python."""
    if archive.is_symlink() or public_archive.sha(archive) != expected_sha256:
        raise ValueError('Compiler archive drift or symlink')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Compiler extraction requires a fresh directory')
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        graph = archive_safety.validate_tar(members)
        destination.mkdir()
        if callable(getattr(tarfile, 'data_filter', None)):
            stream.extractall(destination, members=members, filter='data')
        else:
            stream.extractall(destination, members=members)
    llvm = destination / 'llvm-mingw-20260505-ucrt-macos-universal'
    if not llvm.is_dir() or llvm.is_symlink():
        raise ValueError('Compiler archive root differs')
    required = ['clang', 'ld.lld'] + [f'{arch}-w64-mingw32-{suffix}'
        for arch in ['aarch64', 'arm64ec', 'x86_64', 'i686'] for suffix in ['gcc', 'g++']]
    selected = []
    for name in required:
        path = llvm / 'bin' / name
        if not path.is_file() or not path.resolve().is_relative_to(destination.resolve()):
            raise ValueError('Compiler command missing/foreign: ' + name)
        selected.append(dict(path=str(path.relative_to(destination)),
                             resolved=str(path.resolve().relative_to(destination.resolve())),
                             sha256=public_archive.sha(path)))
    (out / 'compiler-archive.json').write_text(json.dumps(dict(
        state='PRESENT', sha256=expected_sha256, archive_bytes=archive.stat().st_size,
        graph=graph, selected=selected, execution='NOT_ENABLED'), indent=2) + '\n')
    return llvm


def cloud_guard(tool):
    if tool.get('profile') == 'xcode-cloud':
        if not (os.environ.get('CI_BUILD_NUMBER') and os.environ.get('CI_WORKSPACE_PATH')
                and os.environ.get('CI_PRIMARY_REPOSITORY_PATH')):
            raise ValueError('Wine source execution enabled only in Xcode Cloud')
        if tuple(sys.version_info[:2]) < tuple(tool['python_minimum']):
            raise ValueError('Xcode Cloud Wine requires selected Apple Python >=3.9')
    elif os.environ.get('GITHUB_ACTIONS') != 'true' or sys.version_info[:3] != (3, 13, 7):
        raise ValueError('Wine source execution requires GitHub cloud / pinned Python 3.13.7')


def configure_command(source, build_directory, archs):
    """Keep configured runtime directories independent of the staging root."""
    configure = os.path.relpath(source / 'configure', build_directory)
    return [configure, '--prefix=/', '--bindir=/bin', '--libdir=/lib',
            '--datarootdir=/share', '--datadir=/share',
            '--enable-archs=' + ','.join(archs),
            '--disable-tests', '--without-x', '--without-alsa', '--without-capi', '--without-oss',
            '--without-pulse', '--with-coreaudio', '--with-gstreamer', '--with-freetype', '--with-gnutls',
            '--with-vulkan', '--with-sdl', '--with-usb', '--with-fontconfig', '--with-ffmpeg']


def install_command(destination):
    """DESTDIR changes install output, never the compiled BINDIR/LIBDIR/DATADIR."""
    return ['make', 'install', 'DESTDIR=' + str(destination)]


def build(args, lock):
    if not ((_repro_check_18_0 := platform.system()) == (_repro_check_18_1 := 'Darwin') and (_repro_check_18_2 := platform.machine()) == (_repro_check_18_3 := 'arm64')):
        raise AssertionError(_check_message("platform.system() == 'Darwin' and platform.machine() == 'arm64'", {'platform.system()': locals().get('_repro_check_18_0', 'NOT_EVALUATED'), "'Darwin'": locals().get('_repro_check_18_1', 'NOT_EVALUATED'), 'platform.machine()': locals().get('_repro_check_18_2', 'NOT_EVALUATED'), "'arm64'": locals().get('_repro_check_18_3', 'NOT_EVALUATED')}, 'validation failed'))
    cloud_guard(lock['toolchain'])
    if not ((_repro_check_20_0 := args.work) and (_repro_check_20_1 := args.prefix) and (_repro_check_20_2 := args.dependencies) and (_repro_check_20_3 := args.dependencies_sha256) and (_repro_check_20_4 := args.llvm_mingw_archive)):
        raise AssertionError(_check_message('args.work and args.prefix and args.dependencies and args.dependencies_sha256 and args.llvm_mingw_archive', {'args.work': locals().get('_repro_check_20_0', 'NOT_EVALUATED'), 'args.prefix': locals().get('_repro_check_20_1', 'NOT_EVALUATED'), 'args.dependencies': locals().get('_repro_check_20_2', 'NOT_EVALUATED'), 'args.dependencies_sha256': locals().get('_repro_check_20_3', 'NOT_EVALUATED'), 'args.llvm_mingw_archive': locals().get('_repro_check_20_4', 'NOT_EVALUATED')}, 'validation failed'))
    root, prefix = args.work.resolve(), args.prefix.resolve()
    if not (not (_repro_check_21_0 := root.exists())):
        raise AssertionError(_check_message('not root.exists()', {'root.exists()': locals().get('_repro_check_21_0', 'NOT_EVALUATED')}, 'Work directory must be fresh; no stale Makefile/object reuse'))
    dependencies(prefix, args.dependencies.resolve(), args.dependencies_sha256)
    tool = lock['toolchain']
    root.mkdir(parents=True)
    out = root / 'reports'; out.mkdir()
    sdk, clang, clangxx = dependency_driver.toolchain_preflight(tool, out)
    (out / 'effective-build.lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    if not ((_repro_check_25_0 := any((b'os_custom_x18_abi_enabled' in p.read_bytes() for p in (sdk / 'usr/lib/system').glob('*.tbd'))))):
        raise AssertionError(_check_message("any(b'os_custom_x18_abi_enabled' in p.read_bytes() for p in (sdk / 'usr/lib/system').glob('*.tbd'))", {"any((b'os_custom_x18_abi_enabled' in p.read_bytes() for p in (sdk / 'usr/lib/system').glob('*.tbd')))": locals().get('_repro_check_25_0', 'NOT_EVALUATED')}, 'validation failed'))
    versions = {'bison': '3.8.2', 'flex': '2.6.4', 'pkg-config': '3.0.7', 'msgfmt': '1.0'}
    for tool_name, version in versions.items():
        if not ((_repro_check_26_0 := version) in (_repro_check_26_1 := text([str(prefix / 'bin' / tool_name), '--version']))):
            raise AssertionError(_check_message("version in text([str(prefix / 'bin' / tool_name), '--version'])", {'version': locals().get('_repro_check_26_0', 'NOT_EVALUATED'), "text([str(prefix / 'bin' / tool_name), '--version'])": locals().get('_repro_check_26_1', 'NOT_EVALUATED')}, tool_name))
    compiler_archive = args.llvm_mingw_archive.resolve()
    llvm = prepare_compiler(compiler_archive, root / 'toolchain', tool['llvm_mingw_sha256'], out)
    if not ((_repro_check_30_0 := '22.1.5') in (_repro_check_30_1 := text([str(llvm / 'bin/clang'), '--version']))):
        raise AssertionError(_check_message("'22.1.5' in text([str(llvm / 'bin/clang'), '--version'])", {"'22.1.5'": locals().get('_repro_check_30_0', 'NOT_EVALUATED'), "text([str(llvm / 'bin/clang'), '--version'])": locals().get('_repro_check_30_1', 'NOT_EVALUATED')}, 'validation failed'))
    src = root / 'engine/wine'; src.mkdir(parents=True)
    command(['git', 'init', '-q'], out / 'source.log', cwd=src)
    command(['git', 'fetch', '-q', '--depth=1', lock['repository'], lock['revision']], out / 'source.log', cwd=src)
    command(['git', 'checkout', '-q', '--detach', 'FETCH_HEAD'], out / 'source.log', cwd=src)
    if not ((_repro_check_31_0 := text(['git', '-C', str(src), 'rev-parse', 'HEAD'])) == (_repro_check_31_1 := lock['revision'])):
        raise AssertionError(_check_message("text(['git', '-C', str(src), 'rev-parse', 'HEAD']) == lock['revision']", {"text(['git', '-C', str(src), 'rev-parse', 'HEAD'])": locals().get('_repro_check_31_0', 'NOT_EVALUATED'), "lock['revision']": locals().get('_repro_check_31_1', 'NOT_EVALUATED')}, 'validation failed'))
    if not (not (_repro_check_32_0 := text(['git', '-C', str(src), 'status', '--porcelain']))):
        raise AssertionError(_check_message("not text(['git', '-C', str(src), 'status', '--porcelain'])", {"text(['git', '-C', str(src), 'status', '--porcelain'])": locals().get('_repro_check_32_0', 'NOT_EVALUATED')}, 'validation failed'))
    base_headers = source_headers(src)
    for row in lock['required_base_files']:
        if not ((_repro_check_33_0 := blob((src / relative(row['path'])).read_bytes())) == (_repro_check_33_1 := row['git_blob'])):
            raise AssertionError(_check_message("blob((src / relative(row['path'])).read_bytes()) == row['git_blob']", {"blob((src / relative(row['path'])).read_bytes())": locals().get('_repro_check_33_0', 'NOT_EVALUATED'), "row['git_blob']": locals().get('_repro_check_33_1', 'NOT_EVALUATED')}, row['path']))
    release_sources = check_release_sources(src, lock)
    (out / 'release-source-pins.json').write_text(json.dumps(release_sources, indent=2) + '\n')
    for row in lock['overlay']:
        path = src / relative(row['path'])
        if not ((_repro_check_34_0 := (blob(path.read_bytes()) if path.exists() else None)) == (_repro_check_34_1 := row['base_blob'])):
            raise AssertionError(_check_message("(blob(path.read_bytes()) if path.exists() else None) == row['base_blob']", {'blob(path.read_bytes()) if path.exists() else None': locals().get('_repro_check_34_0', 'NOT_EVALUATED'), "row['base_blob']": locals().get('_repro_check_34_1', 'NOT_EVALUATED')}, row['path']))
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(RECIPE / 'source' / row['path'], path)
        if not ((_repro_check_35_0 := sha(path.read_bytes())) == (_repro_check_35_1 := row['sha256'])):
            raise AssertionError(_check_message("sha(path.read_bytes()) == row['sha256']", {'sha(path.read_bytes())': locals().get('_repro_check_35_0', 'NOT_EVALUATED'), "row['sha256']": locals().get('_repro_check_35_1', 'NOT_EVALUATED')}, 'validation failed'))
    keyboard_source = late_source.apply(src, out, command)
    loader_game_mode = prepare_loader_game_mode(src, out)
    header_sources = check_header_sources(src, lock, out, baseline=base_headers)
    hb = root / 'engine/hyperbridge'
    for part in ['include', 'src']:
        shutil.copytree(src / 'third_party/hyperbridge' / part, hb / part)
    shutil.copyfile(src / 'build-recipes/ntdll-include/hb_probe.h', hb / 'include/hb_probe.h')
    env = {k: v for k, v in os.environ.items() if k in
           ['HOME', 'TMPDIR', 'DEVELOPER_DIR', 'LANG', 'LC_ALL', 'SHELL']}
    env['PATH'] = os.pathsep.join([str(prefix / 'bin'), str(llvm / 'bin'), '/usr/bin', '/bin', '/usr/sbin', '/sbin'])
    env['SDKROOT'] = str(sdk)
    env['MACOSX_DEPLOYMENT_TARGET'] = lock['macos_deployment_target']
    env['CC'] = shlex.join([clang])
    env['CXX'] = shlex.join([clangxx])
    mapping = ' '.join(shlex.quote(f'{flag}={root}=/usr/src/macrunner') for flag in
                       ['-ffile-prefix-map', '-fdebug-prefix-map', '-fmacro-prefix-map'])
    env['CFLAGS'] = f'-O2 -arch arm64 -mmacosx-version-min=14.0 -I{shlex.quote(str(prefix / "include"))} {mapping}'
    env['CXXFLAGS'] = env['CFLAGS']
    env['CPPFLAGS'] = '-I' + shlex.quote(str(prefix / 'include'))
    env['LDFLAGS'] = '-arch arm64 -mmacosx-version-min=14.0 -L' + shlex.quote(str(prefix / 'lib'))
    env['PKG_CONFIG_LIBDIR'] = os.pathsep.join([str(prefix / 'lib/pkgconfig'), str(prefix / 'share/pkgconfig')])
    env['PKG_CONFIG_PATH'] = env['PKG_CONFIG_LIBDIR']
    env['PKG_CONFIG'] = str(prefix / 'bin/pkg-config')
    for arch, compiler in [('aarch64', 'aarch64'), ('arm64ec', 'arm64ec'), ('x86_64', 'x86_64'), ('i386', 'i686')]:
        for language, suffix in [('CC', 'gcc'), ('CXX', 'g++')]:
            env[f'{arch}_{language}'] = shlex.join([str(llvm / 'bin' / f'{compiler}-w64-mingw32-{suffix}')])
    jobs = str(args.jobs)
    hb_flags = f'-O2 -std=c11 -fPIC -fvisibility=hidden -arch arm64 -mmacosx-version-min=14.0 -I{shlex.quote(str(hb / "include"))} -MMD -MP {mapping}'
    command(['make', '-f', str(src / 'third_party/hyperbridge/Makefile'), f'SRC_ROOT={hb}', f'BUILD_ROOT={hb}',
             f'CC={env["CC"]}', f'CFLAGS={hb_flags}', '-j' + jobs], out / 'hyperbridge.log', env=env)
    build_dir = src / 'build'; build_dir.mkdir()
    install = root / 'install'
    argv = configure_command(src, build_dir, lock['archs'])
    command(argv, out / 'configure.log', cwd=build_dir, env=env)
    command(['sh', str(RECIPE / 'check-build-srcdir.sh'), str(root)], out / 'srcdir.log', env=env)
    mk = (build_dir / 'Makefile').read_text()
    match = re.search(r'^srcdir\s*=\s*(.+)$', mk, re.M)
    if not ((_repro_check_36_0 := match) and (_repro_check_36_1 := (build_dir / match[1]).resolve()) == (_repro_check_36_2 := src)):
        raise AssertionError(_check_message('match and (build_dir / match[1]).resolve() == src', {'match': locals().get('_repro_check_36_0', 'NOT_EVALUATED'), '(build_dir / match[1]).resolve()': locals().get('_repro_check_36_1', 'NOT_EVALUATED'), 'src': locals().get('_repro_check_36_2', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_37_0 := re.search('^arm64ec_CC\\s*=\\s*\\S', mk, re.M))):
        raise AssertionError(_check_message("re.search(r'^arm64ec_CC\\s*=\\s*\\S', mk, re.M)", {"re.search('^arm64ec_CC\\\\s*=\\\\s*\\\\S', mk, re.M)": locals().get('_repro_check_37_0', 'NOT_EVALUATED')}, 'ARM64EC compiler missing'))
    (out / 'build-inputs.json').write_text(json.dumps(dict(base_revision=lock['revision'],
        keyboard109_source=keyboard_source,
        loader_game_mode_source=loader_game_mode,
        source_lock_sha256=sha((RECIPE / 'wine.lock.json').read_bytes()), dependencies_sha256=args.dependencies_sha256,
        llvm_mingw_archive_sha256=tool['llvm_mingw_sha256'],
        configure_argv=argv, install_argv=install_command(install),
        configured_runtime_directories=dict(prefix='/', bindir='/bin', libdir='/lib', datadir='/share'),
        build_environment={k: env[k] for k in
        ['CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'SDKROOT', 'PKG_CONFIG_LIBDIR']},
        status='NOT_GOLDEN_FULL_SOURCE_BUILD'), indent=2) + '\n')
    command(['make', '-j' + jobs], out / 'build.log', cwd=build_dir, env=env)
    command(install_command(install), out / 'install.log', cwd=build_dir, env=env)
    install_log = (out / 'install.log').read_text(errors='replace')
    skipped = sum('install skipped' in line.lower() for line in install_log.splitlines())
    if not ((_repro_check_38_0 := skipped) == (_repro_check_38_1 := 0)):
        raise AssertionError(_check_message('skipped == 0', {'skipped': locals().get('_repro_check_38_0', 'NOT_EVALUATED'), '0': locals().get('_repro_check_38_1', 'NOT_EVALUATED')}, f'install skipped={skipped}'))
    command([sys.executable, str(RECIPE / 'check-arm64ec-dist.py'), str(install)], out / 'arm64ec.log')
    ec = (out / 'arm64ec.log').read_text()
    counts = re.search(r'EC=(\d+)/(\d+)\s+\.hexpthk=(\d+)\s+\.a64xrm=(\d+)', ec)
    if not ((_repro_check_39_0 := counts)):
        raise AssertionError(_check_message('counts', {'counts': locals().get('_repro_check_39_0', 'NOT_EVALUATED')}, 'ARM64EC count not reported'))
    result = dict(status='FULL_WINE_BUILT_NOT_ACCEPTED', source_revision=lock['revision'], overlay_files=0,
                  ec=int(counts[1]), pe64=int(counts[2]), hexpthk=int(counts[3]), a64xrm=int(counts[4]),
                  install_skipped=skipped, references='D_FUNCTION_SECTION_COMPARISON_PENDING', stands='NOT_RUN',
                   signing=0, notarization=0, publication=0,
                   header_sources_report='header-sources.json', checked_headers=len(header_sources['required_headers']))
    result['loader_game_mode_source_report'] = 'loader-game-mode-source.json'
    result['loader_game_mode_output'] = 'D_EMBEDDED_PLIST_AND_BUNDLE_COMPARISON_PENDING'
    (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--check-header-sources', type=Path)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--prefix', type=Path)
    parser.add_argument('--dependencies', type=Path)
    parser.add_argument('--dependencies-sha256')
    parser.add_argument('--llvm-mingw-archive', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    options = parser.parse_args()
    if sum([options.check_inputs, options.build, options.check_header_sources is not None]) != 1:
        raise ValueError('Choose --check-inputs, --check-header-sources or --build')
    locked = inputs()
    if options.check_header_sources is not None:
        print(json.dumps(check_header_sources(options.check_header_sources, locked), indent=2))
    elif options.check_inputs:
        print(json.dumps(dict(status='INPUTS_OK_NOT_BUILT', files=0, required_base=797, public_release_files=20, late_source_patches=1,
                              lock_sha256=sha((RECIPE / 'wine.lock.json').read_bytes()))))
    else:
        if not ((_repro_check_41_0 := 1) <= (_repro_check_41_1 := options.jobs) <= (_repro_check_41_2 := 32)):
            raise AssertionError(_check_message('1 <= options.jobs <= 32', {'1': locals().get('_repro_check_41_0', 'NOT_EVALUATED'), 'options.jobs': locals().get('_repro_check_41_1', 'NOT_EVALUATED'), '32': locals().get('_repro_check_41_2', 'NOT_EVALUATED')}, 'validation failed'))
        build(options, locked)

#!/usr/bin/env python3
"""Source dependency batch. --check-inputs is offline; --build is cloud only."""
import argparse
import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_fixes import apply_source_fixes
from deps9_support import sdk_zlib_metadata, probe_sdk_zlib, preserve_gnutls_tests
from deps13_support import component_environment
from deps14_support import libvpx_install_name_probe
import source_download
import failure_evidence

HERE = Path(__file__).resolve().parent
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_LOG = 64 * 1024 * 1024
OFFICIAL_HOSTS = {'ftp.gnu.org', 'downloads.xiph.org', 'downloads.sourceforge.net',
                  'distfiles.ariadne.space', 'www.mpg123.de', 'download.gnome.org', 'www.gnupg.org',
                  'gstreamer.freedesktop.org', 'ffmpeg.org', 'download.videolan.org'}
GITHUB_PROJECTS = {'Kitware/CMake', 'ninja-build/ninja', 'westes/flex',
                   'libffi/libffi', 'PCRE2Project/pcre2', 'libusb/libusb', 'libsdl-org/SDL',
                    'openssl/openssl', 'p11-glue/p11-kit', 'fmtlib/fmt', 'Cyan4973/xxHash',
                    'facebook/zstd', 'BLAKE3-team/BLAKE3', 'yhirose/cpp-httplib',
                    'doctest/doctest', 'nonstd-lite/span-lite', 'TartanLlama/expected',
                     'ccache/ccache', 'KhronosGroup/Vulkan-Headers',
                     'libjpeg-turbo/libjpeg-turbo', 'webmproject/libvpx',
                     'Netflix/vmaf', 'Multicorewareinc/x265'}
MESON_SDIST = 'https://files.pythonhosted.org/packages/1b/88/23a6aefb29398b290469914e9ecbdd21803bd53c826aa75e4e2a9b778e98/meson-1.11.0.tar.gz'

def _check_message(expected, actual, note=''):
    def bounded(value):
        if isinstance(value, bytes):
            return 'bytes=' + str(len(value)) + '; prefix_hex=' + value[:32].hex()
        return repr(value)[:600]
    return str(note) + '; expected=' + expected + '; actual=' + repr(
        {key: bounded(value) for key, value in actual.items()})


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_relative(value):
    path = Path(value)
    if not ((_repro_check_0_0 := value) and (not (_repro_check_0_1 := path.is_absolute())) and ((_repro_check_0_2 := '..') not in (_repro_check_0_3 := path.parts))):
        raise AssertionError(_check_message("value and not path.is_absolute() and '..' not in path.parts", {'value': locals().get('_repro_check_0_0', 'NOT_EVALUATED'), 'path.is_absolute()': locals().get('_repro_check_0_1', 'NOT_EVALUATED'), "'..'": locals().get('_repro_check_0_2', 'NOT_EVALUATED'), 'path.parts': locals().get('_repro_check_0_3', 'NOT_EVALUATED')}, 'Unsafe relative path'))
    return path


def official(url):
    parsed = urllib.parse.urlparse(url)
    if not ((_repro_check_1_0 := parsed.scheme) == (_repro_check_1_1 := 'https') and (not (_repro_check_1_2 := parsed.username)) and (not (_repro_check_1_3 := parsed.password))):
        raise AssertionError(_check_message("parsed.scheme == 'https' and not parsed.username and not parsed.password", {'parsed.scheme': locals().get('_repro_check_1_0', 'NOT_EVALUATED'), "'https'": locals().get('_repro_check_1_1', 'NOT_EVALUATED'), 'parsed.username': locals().get('_repro_check_1_2', 'NOT_EVALUATED'), 'parsed.password': locals().get('_repro_check_1_3', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_2_0 := parsed.port) in (_repro_check_2_1 := (None, 443))):
        raise AssertionError(_check_message('parsed.port in (None, 443)', {'parsed.port': locals().get('_repro_check_2_0', 'NOT_EVALUATED'), '(None, 443)': locals().get('_repro_check_2_1', 'NOT_EVALUATED')}, 'validation failed'))
    if parsed.hostname == 'github.com':
        if not ((_repro_check_3_0 := '/'.join(parsed.path.split('/')[1:3])) in (_repro_check_3_1 := GITHUB_PROJECTS)):
            raise AssertionError(_check_message("'/'.join(parsed.path.split('/')[1:3]) in GITHUB_PROJECTS", {"'/'.join(parsed.path.split('/')[1:3])": locals().get('_repro_check_3_0', 'NOT_EVALUATED'), 'GITHUB_PROJECTS': locals().get('_repro_check_3_1', 'NOT_EVALUATED')}, 'Foreign source project'))
    elif parsed.hostname == 'files.pythonhosted.org':
        if not ((_repro_check_4_0 := url) == (_repro_check_4_1 := MESON_SDIST)):
            raise AssertionError(_check_message('url == MESON_SDIST', {'url': locals().get('_repro_check_4_0', 'NOT_EVALUATED'), 'MESON_SDIST': locals().get('_repro_check_4_1', 'NOT_EVALUATED')}, 'Only pinned official Meson source distribution is permitted'))
    elif parsed.hostname == 'gitlab.freedesktop.org':
        if not ((_repro_check_5_0 := parsed.path.startswith('/fontconfig/fontconfig/-/archive/') or
                parsed.path.startswith('/api/v4/projects/890/packages/generic/fontconfig/'))):
            raise AssertionError(_check_message("parsed.path.startswith('/fontconfig/fontconfig/-/archive/')", {"parsed.path.startswith('/fontconfig/fontconfig/-/archive/')": locals().get('_repro_check_5_0', 'NOT_EVALUATED')}, 'Foreign source project'))
    elif parsed.hostname == 'code.videolan.org':
        if not (parsed.path.startswith('/videolan/dav1d/-/archive/') or
                parsed.path == '/videolan/x264.git'):
            raise ValueError(f'Foreign VideoLAN source: expected dav1d archive or x264.git; actual={url!r}')
    elif parsed.hostname == 'gitlab.com':
        if not parsed.path.startswith('/AOMediaCodec/SVT-AV1/-/archive/'):
            raise ValueError(f'Foreign GitLab source: expected AOMediaCodec/SVT-AV1 archive; actual={url!r}')
    else:
        if not ((_repro_check_6_0 := parsed.hostname) in (_repro_check_6_1 := OFFICIAL_HOSTS)):
            raise AssertionError(_check_message('parsed.hostname in OFFICIAL_HOSTS', {'parsed.hostname': locals().get('_repro_check_6_0', 'NOT_EVALUATED'), 'OFFICIAL_HOSTS': locals().get('_repro_check_6_1', 'NOT_EVALUATED')}, 'Foreign source host'))


def read_lock(path=HERE / 'deps.lock.json'):
    lock = json.loads(path.read_text())
    if not ((_repro_check_7_0 := lock['schema']) == (_repro_check_7_1 := 1) and (_repro_check_7_2 := lock['scope']) == (_repro_check_7_3 := 'PARTIAL_WINE_DEPENDENCIES_NOT_WINE_READY')):
        raise AssertionError(_check_message("lock['schema'] == 1 and lock['scope'] == 'PARTIAL_WINE_DEPENDENCIES_NOT_WINE_READY'", {"lock['schema']": locals().get('_repro_check_7_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_7_1', 'NOT_EVALUATED'), "lock['scope']": locals().get('_repro_check_7_2', 'NOT_EVALUATED'), "'PARTIAL_WINE_DEPENDENCIES_NOT_WINE_READY'": locals().get('_repro_check_7_3', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_8_0 := isinstance(lock['components'], list)) and (_repro_check_8_1 := len(lock['components'])) == (_repro_check_8_2 := lock['requested_components'])):
        raise AssertionError(_check_message("isinstance(lock['components'], list) and len(lock['components']) == lock['requested_components']", {"isinstance(lock['components'], list)": locals().get('_repro_check_8_0', 'NOT_EVALUATED'), "len(lock['components'])": locals().get('_repro_check_8_1', 'NOT_EVALUATED'), "lock['requested_components']": locals().get('_repro_check_8_2', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_9_0 := 1) <= (_repro_check_9_1 := lock['requested_components']) <= (_repro_check_9_2 := 100)):
        raise AssertionError(_check_message("1 <= lock['requested_components'] <= 100", {'1': locals().get('_repro_check_9_0', 'NOT_EVALUATED'), "lock['requested_components']": locals().get('_repro_check_9_1', 'NOT_EVALUATED'), '100': locals().get('_repro_check_9_2', 'NOT_EVALUATED')}, 'validation failed'))
    names, supplied = set(), set()
    for row in lock['components']:
        if not ((_repro_check_10_0 := re.fullmatch('[a-z0-9-]+', row['name'])) and (_repro_check_10_1 := row['name']) not in (_repro_check_10_2 := names)):
            raise AssertionError(_check_message("re.fullmatch(r'[a-z0-9-]+', row['name']) and row['name'] not in names", {"re.fullmatch('[a-z0-9-]+', row['name'])": locals().get('_repro_check_10_0', 'NOT_EVALUATED'), "row['name']": locals().get('_repro_check_10_1', 'NOT_EVALUATED'), 'names': locals().get('_repro_check_10_2', 'NOT_EVALUATED')}, 'validation failed'))
        if not ((_repro_check_11_0 := row['version']) and (_repro_check_11_1 := re.fullmatch('[a-f0-9]{64}', row['sha256']))):
            raise AssertionError(_check_message("row['version'] and re.fullmatch(r'[a-f0-9]{64}', row['sha256'])", {"row['version']": locals().get('_repro_check_11_0', 'NOT_EVALUATED'), "re.fullmatch('[a-f0-9]{64}', row['sha256'])": locals().get('_repro_check_11_1', 'NOT_EVALUATED')}, 'validation failed'))
        official(row['url'])
        safe_relative(row.get('source_subdir', '.'))
        if row.get('multi_bit_depth') and (row['name'], row['kind']) != ('x265', 'cmake'):
            raise ValueError(f'Multilib recipe: expected x265/cmake; actual={row["name"]}/{row["kind"]}')
        for item in row.get('copy_trees', []):
            safe_relative(item['source'])
            safe_relative(item['destination'])
        if row.get('configure_ownership'):
            safe_relative(row['configure_ownership']['file'])
        if row.get('source_kind') == 'git':
            expected = ('x264', 'https://code.videolan.org/videolan/x264.git')
            actual = (row['name'], row['url'])
            if actual != expected or not re.fullmatch('[a-f0-9]{40}', row.get('revision', '')):
                raise ValueError(f'Git source pin: expected={expected!r} plus full revision; actual={actual!r}, revision={row.get("revision")!r}')
            safe_relative(row['archive_prefix'].rstrip('/'))
        if not ((_repro_check_12_0 := set(row['depends'])) <= (_repro_check_12_1 := names)):
            raise AssertionError(_check_message("set(row['depends']) <= names", {"set(row['depends'])": locals().get('_repro_check_12_0', 'NOT_EVALUATED'), 'names': locals().get('_repro_check_12_1', 'NOT_EVALUATED')}, 'Dependency is absent or ordered after consumer'))
        if not ((_repro_check_13_0 := row['kind']) in (_repro_check_13_1 := {'autotools', 'cmake-bootstrap', 'ninja-bootstrap', 'openssl', 'meson-bootstrap', 'meson', 'cmake'})):
            raise AssertionError(_check_message("row['kind'] in {'autotools', 'cmake-bootstrap', 'ninja-bootstrap', 'openssl',\n                               'meson-bootstrap', 'meson', 'cmake'}", {"row['kind']": locals().get('_repro_check_13_0', 'NOT_EVALUATED'), "{'autotools', 'cmake-bootstrap', 'ninja-bootstrap', 'openssl', 'meson-bootstrap', 'meson', 'cmake'}": locals().get('_repro_check_13_1', 'NOT_EVALUATED')}, 'validation failed'))
        if not ((_repro_check_14_0 := row['outputs']) and (_repro_check_14_1 := all((safe_relative(x) for x in row['outputs'])))):
            raise AssertionError(_check_message("row['outputs'] and all(safe_relative(x) for x in row['outputs'])", {"row['outputs']": locals().get('_repro_check_14_0', 'NOT_EVALUATED'), "all((safe_relative(x) for x in row['outputs']))": locals().get('_repro_check_14_1', 'NOT_EVALUATED')}, 'validation failed'))
        if not ((_repro_check_15_0 := all((isinstance(x, str) for x in row['args'])))):
            raise AssertionError(_check_message("all(isinstance(x, str) for x in row['args'])", {"all((isinstance(x, str) for x in row['args']))": locals().get('_repro_check_15_0', 'NOT_EVALUATED')}, 'validation failed'))
        if not ((_repro_check_16_0 := re.fullmatch('[a-f0-9]{64}', row['metadata']['sha256']))):
            raise AssertionError(_check_message("re.fullmatch(r'[a-f0-9]{64}', row['metadata']['sha256'])", {"re.fullmatch('[a-f0-9]{64}', row['metadata']['sha256'])": locals().get('_repro_check_16_0', 'NOT_EVALUATED')}, 'Missing metadata provenance'))
        if row['kind'] == 'meson':
            if not ((_repro_check_17_0 := {'meson', 'ninja', 'pkgconf'}) <= (_repro_check_17_1 := set(row['depends']))):
                raise AssertionError(_check_message("{'meson', 'ninja', 'pkgconf'} <= set(row['depends'])", {"{'meson', 'ninja', 'pkgconf'}": locals().get('_repro_check_17_0', 'NOT_EVALUATED'), "set(row['depends'])": locals().get('_repro_check_17_1', 'NOT_EVALUATED')}, 'Meson tools must be ordered'))
        if row['kind'] == 'cmake':
            if not ((_repro_check_18_0 := {'cmake', 'ninja'}) <= (_repro_check_18_1 := set(row['depends']))):
                raise AssertionError(_check_message("{'cmake', 'ninja'} <= set(row['depends'])", {"{'cmake', 'ninja'}": locals().get('_repro_check_18_0', 'NOT_EVALUATED'), "set(row['depends'])": locals().get('_repro_check_18_1', 'NOT_EVALUATED')}, 'CMake tools must be ordered'))
            safe_relative(row.get('source_subdir', '.'))
        if row.get('gst_plugins'):
            if not ((_repro_check_19_0 := row['kind']) == (_repro_check_19_1 := 'meson') and (_repro_check_19_2 := row['name'].startswith(('gstreamer', 'gst-plugins-', 'gst-libav')))):
                raise AssertionError(_check_message("row['kind'] == 'meson' and row['name'].startswith(('gstreamer', 'gst-plugins-'))", {"row['kind']": locals().get('_repro_check_19_0', 'NOT_EVALUATED'), "'meson'": locals().get('_repro_check_19_1', 'NOT_EVALUATED'), "row['name'].startswith(('gstreamer', 'gst-plugins-'))": locals().get('_repro_check_19_2', 'NOT_EVALUATED')}, 'validation failed'))
            if not ((_repro_check_20_0 := len(set(row['gst_plugins']))) == (_repro_check_20_1 := len(row['gst_plugins']))):
                raise AssertionError(_check_message("len(set(row['gst_plugins'])) == len(row['gst_plugins'])", {"len(set(row['gst_plugins']))": locals().get('_repro_check_20_0', 'NOT_EVALUATED'), "len(row['gst_plugins'])": locals().get('_repro_check_20_1', 'NOT_EVALUATED')}, 'validation failed'))
            if not ((_repro_check_21_0 := all((re.fullmatch('[a-z0-9]+', x) for x in row['gst_plugins'])))):
                raise AssertionError(_check_message("all(re.fullmatch(r'[a-z0-9]+', x) for x in row['gst_plugins'])", {"all((re.fullmatch('[a-z0-9]+', x) for x in row['gst_plugins']))": locals().get('_repro_check_21_0', 'NOT_EVALUATED')}, 'validation failed'))
            if not ((_repro_check_22_0 := all(('lib/gstreamer-1.0/libgst' + x + '.dylib' in row['outputs'] for x in row['gst_plugins'])))):
                raise AssertionError(_check_message("all('lib/gstreamer-1.0/libgst' + x + '.dylib' in row['outputs']\n                       for x in row['gst_plugins'])", {"all(('lib/gstreamer-1.0/libgst' + x + '.dylib' in row['outputs'] for x in row['gst_plugins']))": locals().get('_repro_check_22_0', 'NOT_EVALUATED')}, 'Selected plugin output is not required'))
        requirement = row.get('wine_requirement', row['name'])
        if 'wine_requirement' in row:
            if not ((_repro_check_23_0 := requirement) in (_repro_check_23_1 := lock['wine_required'])):
                raise AssertionError(_check_message("requirement in lock['wine_required']", {'requirement': locals().get('_repro_check_23_0', 'NOT_EVALUATED'), "lock['wine_required']": locals().get('_repro_check_23_1', 'NOT_EVALUATED')}, 'Unknown Wine requirement alias'))
        if not ((_repro_check_24_0 := requirement) not in (_repro_check_24_1 := supplied)):
            raise AssertionError(_check_message('requirement not in supplied', {'requirement': locals().get('_repro_check_24_0', 'NOT_EVALUATED'), 'supplied': locals().get('_repro_check_24_1', 'NOT_EVALUATED')}, 'Duplicate supplied requirement'))
        supplied.add(requirement)
        names.add(row['name'])
    if not ((_repro_check_25_0 := len(set(lock['wine_required']))) == (_repro_check_25_1 := len(lock['wine_required'])) == (_repro_check_25_2 := 16)):
        raise AssertionError(_check_message("len(set(lock['wine_required'])) == len(lock['wine_required']) == 16", {"len(set(lock['wine_required']))": locals().get('_repro_check_25_0', 'NOT_EVALUATED'), "len(lock['wine_required'])": locals().get('_repro_check_25_1', 'NOT_EVALUATED'), '16': locals().get('_repro_check_25_2', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_26_0 := lock['remaining_wine_required']) == (_repro_check_26_1 := [x for x in lock['wine_required'] if x not in supplied])):
        raise AssertionError(_check_message("lock['remaining_wine_required'] == [x for x in lock['wine_required'] if x not in supplied]", {"lock['remaining_wine_required']": locals().get('_repro_check_26_0', 'NOT_EVALUATED'), "[x for x in lock['wine_required'] if x not in supplied]": locals().get('_repro_check_26_1', 'NOT_EVALUATED')}, 'validation failed'))
    return lock


def event(out, **fields):
    record = dict(utc=datetime.now(timezone.utc).isoformat(), monotonic_ns=time.monotonic_ns(), **fields)
    with (out / 'timeline.jsonl').open('a') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


def command(argv, cwd, env, log, out, component, deadline, timeout=1800):
    event(out, component=component, state='START', argv=argv, cwd=str(cwd), log=log.name)
    started = time.monotonic()
    with log.open('ab') as stream:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        except Exception as error:
            stream.write(('SPAWN_ERROR: ' + type(error).__name__ + '\n').encode())
            stream.flush()
            failure_evidence.capture(log, out, component, reason='SPAWN_ERROR')
            raise
        reason = None
        while child.poll() is None:
            if time.monotonic() - started > timeout or time.monotonic() > deadline:
                reason = 'TIMEOUT'
            elif log.stat().st_size > MAX_LOG:
                reason = 'LOG_LIMIT_DROPPED'
            if reason:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                break
            time.sleep(0.5)
    event(out, component=component, state=reason or 'EXIT', rc=child.returncode,
          seconds=time.monotonic() - started, log_bytes=log.stat().st_size)
    if not ((_repro_check_27_0 := reason) is (_repro_check_27_1 := None) and (_repro_check_27_2 := child.returncode) == (_repro_check_27_3 := 0)):
        failure_evidence.capture(log, out, component, rc=child.returncode, reason=reason)
        raise AssertionError(_check_message('reason is None and child.returncode == 0', {'reason': locals().get('_repro_check_27_0', 'NOT_EVALUATED'), 'None': locals().get('_repro_check_27_1', 'NOT_EVALUATED'), 'child.returncode': locals().get('_repro_check_27_2', 'NOT_EVALUATED'), '0': locals().get('_repro_check_27_3', 'NOT_EVALUATED')}, f'{component}: {reason or child.returncode}; {log.name}'))


def download(row, destination, out):
    official(row['url'])
    try:
        receipt = source_download.download(row, destination, out)
    except Exception:
        event(out, component=row['name'], state='ARCHIVE_FAILED',
              evidence='public-archives/' + row['name'] + '/receipt.json')
        raise
    event(out, component=row['name'], state='ARCHIVE_PRESENT', bytes=receipt['bytes'],
          sha256=receipt['sha256'], expected_sha256=row['sha256'],
          expected_bytes=receipt['expected_bytes'], transport=receipt['transport'],
          evidence='public-archives/' + row['name'] + '/receipt.json')


def source_root(members):
    if not ((_repro_check_31_0 := members) and (_repro_check_31_1 := len(members)) <= (_repro_check_31_2 := 150000)):
        raise AssertionError(_check_message('members and len(members) <= 150000', {'members': locals().get('_repro_check_31_0', 'NOT_EVALUATED'), 'len(members)': locals().get('_repro_check_31_1', 'NOT_EVALUATED'), '150000': locals().get('_repro_check_31_2', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_32_0 := sum((x.size for x in members))) <= (_repro_check_32_1 := MAX_EXPANDED)):
        raise AssertionError(_check_message('sum(x.size for x in members) <= MAX_EXPANDED', {'sum((x.size for x in members))': locals().get('_repro_check_32_0', 'NOT_EVALUATED'), 'MAX_EXPANDED': locals().get('_repro_check_32_1', 'NOT_EVALUATED')}, 'Expanded source limit'))
    roots = set()
    for member in members:
        path = safe_relative(member.name)
        if not ((_repro_check_33_0 := path.parts)):
            raise AssertionError(_check_message('path.parts', {'path.parts': locals().get('_repro_check_33_0', 'NOT_EVALUATED')}, 'Empty archive member path'))
        roots.add(path.parts[0])
        if not ((_repro_check_34_0 := member.isdir()) or (_repro_check_34_1 := member.isfile()) or (_repro_check_34_2 := member.issym()) or (_repro_check_34_3 := member.islnk())):
            raise AssertionError(_check_message('member.isdir() or member.isfile() or member.issym() or member.islnk()', {'member.isdir()': locals().get('_repro_check_34_0', 'NOT_EVALUATED'), 'member.isfile()': locals().get('_repro_check_34_1', 'NOT_EVALUATED'), 'member.issym()': locals().get('_repro_check_34_2', 'NOT_EVALUATED'), 'member.islnk()': locals().get('_repro_check_34_3', 'NOT_EVALUATED')}, 'validation failed'))
        if member.issym() or member.islnk():
            if not (not (_repro_check_35_0 := Path(member.linkname).is_absolute())):
                raise AssertionError(_check_message('not Path(member.linkname).is_absolute()', {'Path(member.linkname).is_absolute()': locals().get('_repro_check_35_0', 'NOT_EVALUATED')}, 'Absolute archive link'))
            base = str(path.parent) if member.issym() else ''
            target = posixpath.normpath(posixpath.join(base, member.linkname))
            if not ((_repro_check_36_0 := target.split('/')[0]) == (_repro_check_36_1 := path.parts[0])):
                raise AssertionError(_check_message("target.split('/')[0] == path.parts[0]", {"target.split('/')[0]": locals().get('_repro_check_36_0', 'NOT_EVALUATED'), 'path.parts[0]': locals().get('_repro_check_36_1', 'NOT_EVALUATED')}, 'Archive link leaves source root'))
    if not ((_repro_check_37_0 := len(roots)) == (_repro_check_37_1 := 1)):
        raise AssertionError(_check_message('len(roots) == 1', {'len(roots)': locals().get('_repro_check_37_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_37_1', 'NOT_EVALUATED')}, 'Expected one source root'))
    return roots.pop()


def zip_source_root(members):
    if not ((_repro_check_38_0 := members) and (_repro_check_38_1 := len(members)) <= (_repro_check_38_2 := 150000)):
        raise AssertionError(_check_message('members and len(members) <= 150000', {'members': locals().get('_repro_check_38_0', 'NOT_EVALUATED'), 'len(members)': locals().get('_repro_check_38_1', 'NOT_EVALUATED'), '150000': locals().get('_repro_check_38_2', 'NOT_EVALUATED')}, 'validation failed'))
    if not ((_repro_check_39_0 := sum((x.file_size for x in members))) <= (_repro_check_39_1 := MAX_EXPANDED)):
        raise AssertionError(_check_message('sum(x.file_size for x in members) <= MAX_EXPANDED', {'sum((x.file_size for x in members))': locals().get('_repro_check_39_0', 'NOT_EVALUATED'), 'MAX_EXPANDED': locals().get('_repro_check_39_1', 'NOT_EVALUATED')}, 'Expanded source limit'))
    roots = set()
    for member in members:
        if not ((_repro_check_40_0 := '\\') not in (_repro_check_40_1 := member.filename)):
            raise AssertionError(_check_message("'\\\\' not in member.filename", {"'\\\\'": locals().get('_repro_check_40_0', 'NOT_EVALUATED'), 'member.filename': locals().get('_repro_check_40_1', 'NOT_EVALUATED')}, 'Archive backslash path'))
        path = safe_relative(member.filename)
        if not ((_repro_check_41_0 := path.parts)):
            raise AssertionError(_check_message('path.parts', {'path.parts': locals().get('_repro_check_41_0', 'NOT_EVALUATED')}, 'Empty archive member path'))
        roots.add(path.parts[0])
        mode = (member.external_attr >> 16) & 0o170000
        if not ((_repro_check_42_0 := mode) in (_repro_check_42_1 := {0, 32768, 16384})):
            raise AssertionError(_check_message('mode in {0, 0o100000, 0o040000}', {'mode': locals().get('_repro_check_42_0', 'NOT_EVALUATED'), '{0, 32768, 16384}': locals().get('_repro_check_42_1', 'NOT_EVALUATED')}, 'ZIP symlink or special node'))
    if not ((_repro_check_43_0 := len(roots)) == (_repro_check_43_1 := 1)):
        raise AssertionError(_check_message('len(roots) == 1', {'len(roots)': locals().get('_repro_check_43_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_43_1', 'NOT_EVALUATED')}, 'Expected one source root'))
    return roots.pop()


def unpack(archive, destination):
    if not (not (_repro_check_44_0 := destination.exists())):
        raise AssertionError(_check_message('not destination.exists()', {'destination.exists()': locals().get('_repro_check_44_0', 'NOT_EVALUATED')}, 'Extraction must be fresh'))
    destination.mkdir()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as stream:
            root_name = zip_source_root(stream.infolist())
            stream.extractall(destination)
    else:
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            root_name = source_root(members)
            source_download.extract_tar(stream, members, destination,
                evidence=destination.parent / 'reports' / (destination.name + '-links.json'))
    root = destination / root_name
    if not ((_repro_check_45_0 := root.is_dir()) and (_repro_check_45_1 := root.resolve().is_relative_to(destination.resolve()))):
        raise AssertionError(_check_message('root.is_dir() and root.resolve().is_relative_to(destination.resolve())', {'root.is_dir()': locals().get('_repro_check_45_0', 'NOT_EVALUATED'), 'root.resolve().is_relative_to(destination.resolve())': locals().get('_repro_check_45_1', 'NOT_EVALUATED')}, 'validation failed'))
    return root


def environment(prefix, toolchain, clang, clangxx, sdk):
    env = {k: os.environ[k] for k in ['HOME', 'TMPDIR', 'DEVELOPER_DIR'] if k in os.environ}
    env.update(PATH=os.pathsep.join([str(prefix / 'bin'), str(Path(sys.executable).parent),
                                   '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
               LANG='C', LC_ALL='C', SDKROOT=str(sdk), CC=clang, CXX=clangxx,
               MACOSX_DEPLOYMENT_TARGET=toolchain['deployment_target'],
               CFLAGS='-O2 -arch arm64 -mmacosx-version-min=' + toolchain['deployment_target'],
               CXXFLAGS='-O2 -arch arm64 -mmacosx-version-min=' + toolchain['deployment_target'],
               CPPFLAGS='-I' + str(prefix / 'include'), LDFLAGS='-L' + str(prefix / 'lib'),
               PKG_CONFIG_LIBDIR=os.pathsep.join([str(prefix / 'lib/pkgconfig'), str(prefix / 'share/pkgconfig')]),
               PKG_CONFIG_PATH='', PKG_CONFIG=str(prefix / 'bin/pkg-config'), PYTHON=sys.executable,
               am_cv_func_iconv_works='yes')
    return env


def build_steps(row, source, prefix, sdk, jobs, compilers=None):
    cc, cxx = compilers or ('/usr/bin/clang', '/usr/bin/clang++')
    args = [x.format(prefix=prefix, sdk=sdk, cc=cc, cxx=cxx) for x in row['args']]
    if row['kind'] == 'autotools':
        make_args = [x.format(prefix=prefix, sdk=sdk) for x in row.get('make_args', [])]
        steps = [[str(source / 'configure'), '--prefix=' + str(prefix), *args], ['make', '-j' + str(jobs), *make_args]]
        if row.get('test_args'):
            steps.append(['make', *row['test_args'], '-j' + str(jobs), *make_args])
        return [*steps, ['make', 'install', *make_args]]
    if row['kind'] == 'cmake-bootstrap':
        return [[str(source / 'bootstrap'), '--prefix=' + str(prefix), '--parallel=' + str(jobs),
                 '--no-system-libs', '--system-zlib', '--system-bzip2', '--system-curl', '--',
                 '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local'],
                ['make', '-j' + str(jobs)], ['make', 'install']]
    if row['kind'] == 'ninja-bootstrap':
        return [[sys.executable, 'configure.py', '--bootstrap', '--verbose', '--with-python=' + sys.executable]]
    if row['kind'] == 'meson-bootstrap':
        return [[sys.executable, str(source / 'meson.py'), '--version']]
    if row['kind'] == 'meson':
        meson = str(prefix / 'bin/meson')
        steps = [[meson, 'setup', '_repro_build', str(source / row.get('source_subdir', '.')), '--prefix=' + str(prefix),
                  '--libdir=lib', '--buildtype=release', '--default-library=shared',
                  '--wrap-mode=nodownload', *args],
                 [meson, 'compile', '-C', '_repro_build', '-j', str(jobs), '--verbose']]
        if row.get('test_args'):
            steps.append([meson, 'test', '-C', '_repro_build', '--print-errorlogs', *row['test_args']])
        return [*steps, [meson, 'install', '-C', '_repro_build', '--no-rebuild']]
    if row['kind'] == 'cmake':
        cmake, ctest = str(prefix / 'bin/cmake'), str(prefix / 'bin/ctest')
        configured_source = source / row.get('source_subdir', '.')
        build_dir = row.get('build_dir', '_repro_build')
        safe_relative(build_dir)
        preliminary = []
        if row.get('multi_bit_depth'):
            for depth in (10, 12):
                child = dict(row, multi_bit_depth=False, build_dir=f'_repro_{depth}bit',
                             args=['-DHIGH_BIT_DEPTH=ON', '-DEXPORT_C_API=OFF',
                                   '-DENABLE_SHARED=OFF', '-DENABLE_CLI=OFF',
                                   '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
                                   *(['-DENABLE_HDR10_PLUS=ON'] if depth == 10 else ['-DMAIN12=ON'])])
                preliminary.extend(build_steps(child, source, prefix, sdk, jobs, compilers)[:2])
            args += ['-DLINKED_10BIT=ON', '-DLINKED_12BIT=ON',
                     '-DEXTRA_LIB=' + ';'.join(str(source / f'_repro_{d}bit/libx265.a') for d in (10, 12))]
        targets = row.get('build_targets', [])
        components = row.get('install_components', [])
        for values in [targets, components]:
            if not isinstance(values, list) or any(not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]+', value) for value in values):
                raise ValueError('Explicit CMake target/component names differ')
        steps = [[cmake, '-S', str(configured_source), '-B', build_dir, '-G', 'Ninja',
                  '-DCMAKE_MAKE_PROGRAM=' + str(prefix / 'bin/ninja'),
                  '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(prefix),
                  '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_PREFIX_PATH=' + str(prefix),
                  '-DCMAKE_OSX_ARCHITECTURES=arm64', '-DCMAKE_OSX_SYSROOT=' + str(sdk),
                  '-DCMAKE_INSTALL_RPATH=' + str(prefix / 'lib'),
                  '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
                  '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF',
                  '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
                  '-DFETCHCONTENT_FULLY_DISCONNECTED=ON', *args],
                  [cmake, '--build', build_dir, '--parallel', str(jobs), '--verbose',
                   *(['--target', *targets] if targets else [])]]
        if row.get('test_args'):
            steps.append([ctest, '--test-dir', build_dir, '--output-on-failure',
                          '--parallel', str(jobs), *row['test_args']])
        install = [[cmake, '--install', build_dir, '--component', value] for value in components] if components else [[cmake, '--install', build_dir]]
        return [*preliminary, *steps, *install]
    return [['/usr/bin/perl', str(source / 'Configure'), '--prefix=' + str(prefix),
             '--openssldir=' + str(prefix / 'etc/ssl'), '--libdir=lib', *args],
            ['make', '-j' + str(jobs)], ['make', 'test'], ['make', 'install_sw']]


def install_meson(source, prefix):
    # Source-only installation: no pip, wheel, setuptools or implicit network bootstrap.
    shutil.copytree(source / 'mesonbuild', prefix / 'share/meson/mesonbuild')
    launcher = prefix / 'bin/meson'
    launcher.write_text('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n'
                        'sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "share/meson"))\n'
                        'from mesonbuild.mesonmain import main\nraise SystemExit(main())\n')
    launcher.chmod(0o755)


def meson_source_ownership(source, out, component, prefix=None):
    path = source / '_repro_build/meson-info/intro-buildsystem_files.json'
    paths = json.loads(path.read_text())
    if not ((_repro_check_46_0 := isinstance(paths, list)) and (_repro_check_46_1 := paths) and (_repro_check_46_2 := all((isinstance(x, str) for x in paths)))):
        raise AssertionError(_check_message('isinstance(paths, list) and paths and all(isinstance(x, str) for x in paths)', {'isinstance(paths, list)': locals().get('_repro_check_46_0', 'NOT_EVALUATED'), 'paths': locals().get('_repro_check_46_1', 'NOT_EVALUATED'), 'all((isinstance(x, str) for x in paths))': locals().get('_repro_check_46_2', 'NOT_EVALUATED')}, 'validation failed'))
    # Meson records the exact configured input files; keep the full evidence, not a guessed srcdir.
    shutil.copyfile(path, out / f'{component}-buildsystem-files.json')
    # Meson also records external generator executables, not just source files.
    # Generator executables are tools. Admit exact identities, never their directory.
    allowed_names = {'gstreamer': ['flex', 'bison'], 'libvmaf': ['xxd'],
                     'fontconfig': ['gperf']}.get(component, [])
    selected_tools = {}
    for name in allowed_names:
        if name in {'xxd', 'gperf'}:
            candidate = Path('/usr/bin') / name
            owner = 'PLATFORM_TOOL'
        elif prefix is not None:
            candidate = prefix / 'bin' / name
            owner = 'SOURCE_BUILT'
            if not candidate.resolve().is_relative_to(prefix.resolve()):
                raise AssertionError(f'Meson generator: expected=inside owned prefix; actual={candidate.resolve()}')
        else:
            continue
        if candidate.is_file():
            selected_tools[str(candidate.resolve())] = dict(name=name, path=str(candidate),
                                                           sha256=file_sha(candidate), owner=owner)
    external = [x for x in paths if not Path(x).resolve().is_relative_to(source.resolve())]
    foreign = [x for x in external if str(Path(x).resolve()) not in selected_tools]
    if not (not (_repro_check_47_0 := foreign)):
        raise AssertionError(_check_message('not foreign', {'foreign': locals().get('_repro_check_47_0', 'NOT_EVALUATED')}, 'Meson configured foreign source files: ' + repr(foreign[:5])))
    return dict(state='PRESENT', configured_files=len(paths), foreign_files=0,
                source_files=len(paths) - len(external),
                build_tools=[selected_tools[str(Path(x).resolve())] for x in external],
                raw_path=f'{component}-buildsystem-files.json', sha256=file_sha(path))


def cmake_source_ownership(source, configured_source, prefix, sdk, out, component, build_directory='_repro_build'):
    safe_relative(build_directory)
    build_dir = source / build_directory
    cache = build_dir / 'CMakeCache.txt'
    reply = build_dir / '.cmake/api/v1/reply'
    files = sorted(reply.glob('*.json'))
    target = out / f'{component}-cmake-source{("-" + build_directory) if build_directory != "_repro_build" else ""}'
    target.mkdir()
    ledger = []
    for path in [cache, *files]:
        shutil.copyfile(path, target / path.name)
        ledger.append(dict(path=str((target / path.name).relative_to(out)), sha256=file_sha(path)))
    # Keep failed source-selection evidence before any validation can raise.
    values = dict(line.split('=', 1) for line in cache.read_text().splitlines()
                  if line and not line.startswith(('#', '//')) and '=' in line)
    if not ((_repro_check_48_0 := Path(values['CMAKE_HOME_DIRECTORY:INTERNAL']).resolve()) == (_repro_check_48_1 := configured_source.resolve())):
        raise AssertionError(_check_message("Path(values['CMAKE_HOME_DIRECTORY:INTERNAL']).resolve() == configured_source.resolve()", {"Path(values['CMAKE_HOME_DIRECTORY:INTERNAL']).resolve()": locals().get('_repro_check_48_0', 'NOT_EVALUATED'), 'configured_source.resolve()': locals().get('_repro_check_48_1', 'NOT_EVALUATED')}, 'CMake configured foreign source root'))
    if not ((_repro_check_49_0 := files) and (_repro_check_49_1 := any((x.name.startswith('cmakeFiles-v1-') for x in files)))):
        raise AssertionError(_check_message("files and any(x.name.startswith('cmakeFiles-v1-') for x in files)", {'files': locals().get('_repro_check_49_0', 'NOT_EVALUATED'), "any((x.name.startswith('cmakeFiles-v1-') for x in files))": locals().get('_repro_check_49_1', 'NOT_EVALUATED')}, 'Missing CMake input reply'))
    if not ((_repro_check_50_0 := any((x.name.startswith('codemodel-v2-') for x in files)))):
        raise AssertionError(_check_message("any(x.name.startswith('codemodel-v2-') for x in files)", {"any((x.name.startswith('codemodel-v2-') for x in files))": locals().get('_repro_check_50_0', 'NOT_EVALUATED')}, 'Missing CMake target reply'))
    permitted = [x.resolve() for x in [source, prefix, sdk]]
    checked, foreign = 0, []
    for path in files:
        data = json.loads(path.read_text())
        candidates = data.get('inputs', []) if path.name.startswith('cmakeFiles-v1-') else []
        if path.name.startswith('target-'):
            candidates = data.get('sources', [])
        for row in candidates:
            item = Path(row['path'])
            if not item.is_absolute():
                item = (build_dir if row.get('isGenerated') else configured_source) / item
            item = item.resolve()
            checked += 1
            if not any(item.is_relative_to(root) for root in permitted):
                foreign.append(str(item))
    if not ((_repro_check_51_0 := checked)):
        raise AssertionError(_check_message('checked', {'checked': locals().get('_repro_check_51_0', 'NOT_EVALUATED')}, 'No configured CMake source inputs'))
    if not (not (_repro_check_52_0 := foreign)):
        raise AssertionError(_check_message('not foreign', {'foreign': locals().get('_repro_check_52_0', 'NOT_EVALUATED')}, 'CMake configured foreign source files: ' + repr(foreign[:5])))
    return dict(state='PRESENT', configured_files=checked, foreign_files=0, raw_files=ledger)


def licenses(source, prefix, name):
    paths = {x for pattern in ['LICENSE*', 'COPYING*', 'Copyright.txt', 'Copyright.*']
             for x in source.glob(pattern) if x.is_file()}
    for relative in ['docs/LICENSE.TXT', 'docs/FTL.TXT', 'docs/GPLv2.TXT', 'COPYING.LESSER',
                     'LICENSES/LGPL-2.1-or-later.txt', 'LICENSES/MIT.txt',
                     'gettext-runtime/intl/COPYING.LIB']:
        path = source / relative
        if path.is_file():
            paths.add(path)
    if not ((_repro_check_53_0 := paths)):
        raise AssertionError(_check_message('paths', {'paths': locals().get('_repro_check_53_0', 'NOT_EVALUATED')}, f'{name}: missing license evidence'))
    target = prefix / 'share/licenses' / name
    target.mkdir(parents=True)
    result = []
    for path in sorted(paths):
        relative = path.relative_to(source)
        destination = target / str(relative).replace('/', '__')
        shutil.copyfile(path, destination)
        result.append(dict(source_path=str(relative), path=str(destination.relative_to(prefix)),
                           sha256=file_sha(destination)))
    return result


def inspect_plugin_report(text, plugin_path, version):
    fields = dict(re.findall(r'^\s*(Filename|Version)\s+(.+?)\s*$', text, re.MULTILINE))
    if not ((_repro_check_54_0 := fields.get('Version')) == (_repro_check_54_1 := version)):
        raise AssertionError(_check_message("fields.get('Version') == version", {"fields.get('Version')": locals().get('_repro_check_54_0', 'NOT_EVALUATED'), 'version': locals().get('_repro_check_54_1', 'NOT_EVALUATED')}, 'GStreamer selected wrong plugin version'))
    if not ((_repro_check_55_0 := Path(fields.get('Filename', '')).resolve()) == (_repro_check_55_1 := plugin_path.resolve())):
        raise AssertionError(_check_message("Path(fields.get('Filename', '')).resolve() == plugin_path.resolve()", {"Path(fields.get('Filename', '')).resolve()": locals().get('_repro_check_55_0', 'NOT_EVALUATED'), 'plugin_path.resolve()': locals().get('_repro_check_55_1', 'NOT_EVALUATED')}, 'GStreamer loaded foreign plugin'))
    return dict(state='PRESENT', loaded_path=str(plugin_path), version=version)


def gst_plugin_probes(row, source, prefix, env, out, deadline):
    plugin_env = dict(env)
    plugin_env.update(GST_PLUGIN_SYSTEM_PATH_1_0=str(prefix / 'lib/gstreamer-1.0'),
                      GST_PLUGIN_PATH_1_0='',
                      GST_PLUGIN_SCANNER_1_0=str(prefix / 'libexec/gstreamer-1.0/gst-plugin-scanner'),
                      GST_REGISTRY_1_0=str(source / '_repro-plugin-registry.bin'))
    event(out, component=row['name'], state='PLUGIN_CHILD_ENV', environment=plugin_env,
          sha256=digest(json.dumps(plugin_env, sort_keys=True, separators=(',', ':')).encode()))
    probes = []
    for name in row['gst_plugins']:
        plugin_path = prefix / ('lib/gstreamer-1.0/libgst' + name + '.dylib')
        log = out / (row['name'] + '-inspect-' + name + '.log')
        command([str(prefix / 'bin/gst-inspect-1.0'), '--plugin', str(plugin_path)],
                source, plugin_env, log, out, row['name'], deadline, timeout=30)
        report = inspect_plugin_report(log.read_text(errors='replace'), plugin_path, row['version'])
        probes.append(dict(plugin=name, raw_path=log.name, raw_sha256=file_sha(log), **report))
    return probes


def inventory(prefix):
    rows = []
    for path in sorted(prefix.rglob('*')):
        if not ((_repro_check_56_0 := path.resolve().is_relative_to(prefix.resolve()))):
            raise AssertionError(_check_message('path.resolve().is_relative_to(prefix.resolve())', {'path.resolve().is_relative_to(prefix.resolve())': locals().get('_repro_check_56_0', 'NOT_EVALUATED')}, 'Installed symlink leaves prefix'))
        if path.is_file():
            rows.append(dict(path=str(path.relative_to(prefix)), sha256=file_sha(path), bytes=path.stat().st_size,
                             symlink=os.readlink(path) if path.is_symlink() else None))
        else:
            if not ((_repro_check_57_0 := path.is_dir())):
                raise AssertionError(_check_message('path.is_dir()', {'path.is_dir()': locals().get('_repro_check_57_0', 'NOT_EVALUATED')}, 'Broken link or unsupported installed node'))
    if not ((_repro_check_58_0 := rows)):
        raise AssertionError(_check_message('rows', {'rows': locals().get('_repro_check_58_0', 'NOT_EVALUATED')}, 'Empty installed prefix'))
    return rows


def toolchain_preflight(tool, out):
    """Capture selected tools before download, including a failed SDK check."""
    report = {'status': 'STARTED', 'expected': dict(tool), 'actual': {}, 'commands': [],
              'developer_dir': os.environ.get('DEVELOPER_DIR', 'NOT_ENABLED')}
    path = out / 'toolchain-preflight.json'
    def output(name, argv):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=30)
        report['commands'].append({'argv': argv, 'rc': result.returncode, 'stdout': result.stdout})
        report['actual'][name] = result.stdout.strip()
        if result.returncode:
            raise AssertionError(_check_message('command rc=0',
                                                {'argv': argv, 'rc': result.returncode,
                                                 'stdout': result.stdout}))
        return result.stdout.strip()
    try:
        actual = report['actual']
        output('xcode', ['xcodebuild', '-version'])
        output('sdk', ['xcrun', '--show-sdk-version'])
        sdk = output('sdk_path', ['xcrun', '--show-sdk-path'])
        clang = output('clang_path', ['xcrun', '--find', 'clang'])
        clangxx = output('clangxx_path', ['xcrun', '--find', 'clang++'])
        output('apple_clang', [clang, '--version'])
        if tool.get('profile') == 'xcode-cloud':
            output('apple_ld', ['xcrun', 'ld', '-v'])
            output('macos_build', ['sw_vers', '-buildVersion'])
            if not re.fullmatch(r"Xcode " + str(tool['xcode_major']) + r"(?:\.\d+)*\nBuild version [A-Za-z0-9]+", actual['xcode']):
                raise ValueError('Xcode Cloud: expected Xcode major 27; actual=' + actual['xcode'])
            if not re.search(r'PROJECT:ld-' + re.escape(tool['ld']) + r'(?![\d.])', actual['apple_ld']):
                raise ValueError('Xcode Cloud: expected ld-' + tool['ld'] + '; actual=' + actual['apple_ld'])
            checks = [('sdk', tool['sdk'])]
        else:
            expected_xcode = f"Xcode {tool['xcode']}\nBuild version {tool['xcode_build']}"
            checks = [('xcode', expected_xcode), ('sdk', tool['sdk'])]
        for key, expected in checks:
            if actual[key] != expected:
                raise AssertionError(_check_message(str(expected), {key: actual[key]}, key+' differs'))
        expected_clang = tool.get('apple_clang', 'Apple clang version 21.')
        if expected_clang not in actual['apple_clang']:
            raise AssertionError(_check_message(expected_clang,
                                                 {'apple_clang': actual['apple_clang']}))
        if tool.get('profile') == 'xcode-cloud':
            tool.update(python=sys.version.split()[0], python_path=sys.executable,
                        xcode=actual['xcode'].splitlines()[0].split(' ', 1)[1],
                        xcode_build=actual['xcode'].splitlines()[1].split(' ', 2)[2],
                        apple_clang=actual['apple_clang'], apple_ld=actual['apple_ld'],
                        macos_build=actual['macos_build'], exact_pins_state='MEASURED_BEFORE_SOURCES')
            report['measured_effective_toolchain'] = dict(tool)
        report['status'] = 'PRESENT'
        return Path(sdk), clang, clangxx
    except Exception as exc:
        report.update(status='FAILED', first_error=str(exc))
        raise
    finally:
        path.write_text(json.dumps(report, indent=2)+'\n')


def output(argv, env=None, raw_log=None):
    """Short, bounded-duration tool/version queries; never a build invocation."""
    result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    raw = result.stdout
    if isinstance(raw, str):
        raw = raw.encode()
    if raw_log is not None:
        raw_log.write_bytes(raw)
    if result.returncode != 0 or len(raw) > 1024 * 1024:
        raise ValueError(f'Tool query: expected rc=0 and bytes<=1048576; actual rc={result.returncode}, bytes={len(raw)}, argv={argv!r}, stdout_sha256={digest(raw)}')
    return raw.decode(errors='replace').strip()


def git_source(row, root, archive, env, out, deadline):
    """Cloud-only, complete x264 history; pin both HEAD and byte-exact raw archive."""
    source = root / (row['name'] + '-source')
    source.mkdir()
    git = ['/usr/bin/git', '-C', str(source)]
    steps = [git + ['init'],
             git + ['-c', 'protocol.file.allow=never', 'fetch', '--no-tags', row['url'], row['revision']],
             git + ['checkout', '--detach', 'FETCH_HEAD'],
             git + ['update-ref', 'refs/remotes/origin/master', row['revision']],
             git + ['archive', '--format=tar', '--prefix=' + row['archive_prefix'],
                    '--output=' + str(archive), 'HEAD']]
    for number, argv in enumerate(steps, 1):
        command(argv, source, env, out / f'{row["name"]}-source-{number}.log',
                out, row['name'], deadline, timeout=600)
    revision = output(git + ['rev-parse', 'HEAD'], env=env)
    count = output(git + ['rev-list', '--count', 'HEAD'], env=env)
    sha = file_sha(archive)
    actual = dict(revision=revision, revision_count=count, sha256=sha, archive_bytes=archive.stat().st_size)
    expected = dict(revision=row['revision'], revision_count=str(row['revision_count']), sha256=row['sha256'])
    event(out, component=row['name'], state='GIT_SOURCE_PIN', expected=expected, actual=actual)
    if any(actual[k] != v for k, v in expected.items()) or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError(f'Git source differs: expected={expected!r}, max_bytes={MAX_ARCHIVE}; actual={actual!r}')
    return source


def configure_source_ownership(row, source, out):
    rule = row['configure_ownership']
    path = source / rule['file']
    raw = path.read_bytes()
    target = out / f'{row["name"]}-configure-source.txt'
    target.write_bytes(raw)
    values = dict(line.split('=', 1) for line in raw.decode().splitlines()
                  if '=' in line and not line.startswith('#'))
    value = values.get(rule['key'])
    actual = ((source / value).resolve() if value is not None else None)
    expected = source.resolve()
    receipt = dict(state='PRESENT' if actual == expected else 'FAILED',
                   expected=str(expected), actual=str(actual) if actual else None,
                   raw_file=target.name, sha256=digest(raw))
    (out / f'{row["name"]}-configure-ownership.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if actual != expected:
        raise ValueError(f'Configure selected foreign source: expected={str(expected)!r}; actual={str(actual)!r}, key={rule["key"]!r}')
    if row.get('ffmpeg_external'):
        features = {name: values.get('CONFIG_' + name.upper()) for name in row['ffmpeg_external']}
        (out / 'ffmpeg-configured-features.json').write_text(json.dumps(dict(
            expected={name: 'yes' for name in features}, actual=features), indent=2) + '\n')
        if any(value != 'yes' for value in features.values()):
            raise ValueError(f'FFmpeg configured codec closure: expected=all yes; actual={features!r}')
        receipt['configured_features'] = features
    return receipt


def flex_libfl_probe(prefix, env, out, deadline):
    """Confirm Darwin caller-supplied yylex ABI, then run an owned generated lexer."""
    value = output(['/usr/bin/nm', '-m', str(prefix / 'lib/libfl.dylib')],
                   env=env, raw_log=out / 'flex-libfl-nm.raw.txt')
    dynamic_lines = [line for line in value.splitlines() if 'dynamically looked up' in line]
    symbols = re.findall(r'external\s+(_\w+)\s+\(dynamically looked up\)', '\n'.join(dynamic_lines))
    if symbols != ['_yylex'] or len(dynamic_lines) != 1:
        raise ValueError(f'libfl caller symbol ABI: expected=[_yylex] exactly once; actual={symbols!r}, lines={dynamic_lines!r}')
    source = out / 'flex-libfl-probe.l'
    generated, executable = out / 'flex-libfl-probe.c', out / 'flex-libfl-probe'
    source.write_text('%{\n#include <string.h>\nstatic int provided;\n'
        '#define YY_INPUT(buf,result,max_size) do { if (!provided) { memcpy(buf,"REPRO",5); result=5; provided=1; } else result=0; } while (0)\n'
        '%}\n%%\nREPRO { puts("FLEX_PROBE_OK"); }\n. { return 1; }\n%%\n')
    command([str(prefix / 'bin/flex'), '-o', str(generated), str(source)], out, env,
            out / 'flex-probe-generate.log', out, 'flex', deadline)
    command([env['CC'], '-arch', 'arm64', '-mmacosx-version-min=' + env['MACOSX_DEPLOYMENT_TARGET'],
             str(generated), '-L' + str(prefix / 'lib'), '-Wl,-rpath,' + str(prefix / 'lib'),
             '-lfl', '-o', str(executable)], out, env, out / 'flex-probe-compile.log', out, 'flex', deadline)
    command([str(executable)], out, env, out / 'flex-probe-run.log', out, 'flex', deadline)
    observed = (out / 'flex-probe-run.log').read_text().strip()
    if observed != 'FLEX_PROBE_OK':
        raise ValueError(f'libfl generated lexer: expected=FLEX_PROBE_OK; actual={observed!r}')
    return dict(kind='flex_libfl_caller_abi', state='PRESENT', dynamically_looked_up=symbols,
                owned_lexer_result=observed, raw_nm='flex-libfl-nm.raw.txt', raw_run='flex-probe-run.log')


def cloud_guard(tool):
    """Validate execution/tools; private publication is the job wrapper's scope."""
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ValueError('Dependency sources require native Darwin arm64')
    if not (os.environ.get('GITHUB_ACTIONS') == 'true' or
            (os.environ.get('CI_WORKSPACE_PATH') and os.environ.get('CI_PRIMARY_REPOSITORY_PATH'))):
        raise ValueError('Dependency source execution/download allowed only in the cloud')
    if tool.get('profile') == 'xcode-cloud':
        if tuple(sys.version_info[:2]) < tuple(tool['python_minimum']):
            raise ValueError('Xcode Cloud: expected Python >=3.9; actual=' + sys.version.split()[0])
        if not os.environ.get('CI_BUILD_NUMBER'):
            raise ValueError('Xcode Cloud: expected CI_BUILD_NUMBER; actual=NOT_ENABLED')
    elif sys.version.split()[0] != tool['python']:
        raise ValueError('Dependency sources require the pinned Python version')


def build(args, lock):
    cloud_guard(lock['toolchain'])  # Before work creation, source execution or downloads.
    prepared = getattr(args, 'source_inputs', None)
    if prepared is not None:
        import preflight_sources
        preflight_sources.validate(prepared, lock)  # Before SDK probes or any compiler.
    root = args.work.resolve()
    if not (not (_repro_check_62_0 := root.exists()) and (not (_repro_check_62_1 := re.search('\\s', str(root))))):
        raise AssertionError(_check_message("not root.exists() and not re.search(r'\\s', str(root))", {'root.exists()': locals().get('_repro_check_62_0', 'NOT_EVALUATED'), "re.search('\\\\s', str(root))": locals().get('_repro_check_62_1', 'NOT_EVALUATED')}, 'Fresh work path without whitespace required'))
    tool = lock['toolchain']
    root.mkdir(parents=True)
    prefix, out = root / 'prefix', root / 'reports'
    prefix.mkdir(); out.mkdir()
    if prepared is not None:
        shutil.copyfile(Path(prepared) / 'reports/RESULT.json', out / 'source-inputs-RESULT.json')
    sdk, clang, clangxx = toolchain_preflight(tool, out)
    for directory in ['bin', 'lib/pkgconfig', 'share/pkgconfig', 'include']:
        (prefix / directory).mkdir(parents=True, exist_ok=True)
    if tool.get('profile') == 'xcode-cloud':
        (out / 'effective-build.lock.json').write_text(json.dumps(lock, indent=2)+'\n')
    sdk_zlib_metadata(sdk, prefix, out)
    driver_sha, lock_sha = file_sha(Path(__file__)), file_sha(HERE / 'deps.lock.json')
    receipt = dict(schema=1, scope=lock['scope'], source_built=False, components={},
                   remaining_wine_required=lock['remaining_wine_required'], files=[],
                   driver_sha256=driver_sha, lock_sha256=lock_sha, status='BUILD_STARTED',
                   toolchain=tool, platform_dependencies=lock['platform_dependencies'],
                   runtime_gaps=lock['runtime_gaps'],
                   wine='NOT_ENABLED_INCOMPLETE_PREFIX', signing=0, notarization=0, publication=0)
    receipt.update(failures=[], skipped_components=[], component_states={})
    completed_names = set()
    current, phase = None, 'START'
    deadline = time.monotonic() + args.minutes * 60
    try:
        for row in lock['components']:
            current = row['name']
            blockers = [name for name in row['depends'] if name not in completed_names]
            reason = 'DEPENDENCY_FAILED_OR_NOT_ENABLED' if blockers else ('BATCH_DEADLINE' if time.monotonic() >= deadline else None)
            if reason:
                skipped = dict(component=current, state='NOT_ENABLED', reason=reason, dependencies=blockers)
                receipt['skipped_components'].append(skipped)
                receipt['component_states'][current] = skipped
                event(out, component=current, state='NOT_ENABLED', reason=reason, dependencies=blockers)
                (out / 'dependency-manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
                continue
            try:
                source = None
                current, phase = row['name'], 'DOWNLOAD'
                if not ((_repro_check_66_0 := time.monotonic()) < (_repro_check_66_1 := deadline)):
                    raise AssertionError(_check_message('time.monotonic() < deadline', {'time.monotonic()': locals().get('_repro_check_66_0', 'NOT_EVALUATED'), 'deadline': locals().get('_repro_check_66_1', 'NOT_EVALUATED')}, 'Batch deadline reached'))
                archive = root / (current + '.source.tar')
                env = environment(prefix, tool, clang, clangxx, sdk)
                target = row.get('deployment_target', tool['deployment_target'])
                env['MACOSX_DEPLOYMENT_TARGET'] = target
                for key in ['CFLAGS', 'CXXFLAGS']:
                    env[key] = '-O2 -arch arm64 -mmacosx-version-min=' + target
                if current == 'gnutls':
                    env['REPRO109_PORT_PYTHON'] = sys.executable
                    env['REPRO109_PORT_PROBE'] = str(HERE/'port_probe.py')
                env = component_environment(row, env, prefix, HERE, out, event)
                event(out, component=current, state='CHILD_ENV', environment=env,
                      sha256=digest(json.dumps(env, sort_keys=True, separators=(',', ':')).encode()),
                       parent_inherited_keys=sorted(set(env).intersection({'HOME', 'TMPDIR', 'DEVELOPER_DIR'})))
                if current == 'libpng':
                    probe_sdk_zlib(prefix, env, out, deadline, command)
                if prepared is not None:
                    phase = 'PREPARED_SOURCE_COPY'
                    source = preflight_sources.copy_source(row, prepared, archive, root)
                    event(out, component=current, state='PREPARED_SOURCE_PRESENT',
                          bytes=archive.stat().st_size, sha256=file_sha(archive),
                          evidence='source-inputs-RESULT.json')
                elif row.get('source_kind') == 'git':
                    source = git_source(row, root, archive, env, out, deadline)
                else:
                    download(row, archive, out)
                    phase = 'EXTRACT'
                    source = unpack(archive, root / (current + '-source'))
                # The accepted libvorbis recipe removes an obsolete Apple compiler option.
                if current == 'libvorbis':
                    configure = source / 'configure'
                    previous = file_sha(configure)
                    text = configure.read_text()
                    count = text.count(' -force_cpusubtype_ALL')
                    configure.write_text(text.replace(' -force_cpusubtype_ALL', ''))
                    event(out, component=current, state='SOURCE_TRANSFORM',
                          transformation='remove_obsolete_force_cpusubtype_ALL', replacements=count,
                          input_sha256=previous, output_sha256=file_sha(configure))
                phase = 'SOURCE_TRANSFORM'
                apply_source_fixes(row, source, out, event)
                phase = 'BUILD'
                ownership = None
                steps = build_steps(row, source, prefix, sdk, args.jobs, (clang, clangxx))
                for number, argv in enumerate(steps, 1):
                    cmake_configure = row['kind'] == 'cmake' and '-S' in argv and '-B' in argv
                    if cmake_configure:
                        build_directory = argv[argv.index('-B') + 1]
                        query = source / build_directory / '.cmake/api/v1/query'
                        query.mkdir(parents=True)
                        for name in ['cmakeFiles-v1', 'codemodel-v2']:
                            (query / name).touch()
                    command(argv, source, env, out / f'{current}-{number}.log', out, current, deadline)
                    if number == 1 and row['kind'] == 'meson':
                        ownership = meson_source_ownership(source, out, current, prefix)
                    if cmake_configure:
                        observed = cmake_source_ownership(source, source / row.get('source_subdir', '.'),
                                                         prefix, sdk, out, current, build_directory)
                        if ownership is None:
                            ownership = []
                        ownership.append(observed)
                    if number == 1 and row.get('configure_ownership'):
                        ownership = configure_source_ownership(row, source, out)
                if not (not (_repro_check_67_0 := any(('install skipped' in line.lower() for path in out.glob(f'{current}-*.log') for line in path.read_text(errors='replace').splitlines())))):
                    raise AssertionError(_check_message("not any('install skipped' in line.lower() for path in out.glob(f'{current}-*.log')\n                           for line in path.read_text(errors='replace').splitlines())", {"any(('install skipped' in line.lower() for path in out.glob(f'{current}-*.log') for line in path.read_text(errors='replace').splitlines()))": locals().get('_repro_check_67_0', 'NOT_EVALUATED')}, 'install skipped found'))
                if row['kind'] == 'ninja-bootstrap':
                    shutil.copyfile(source / 'ninja', prefix / 'bin/ninja')
                    (prefix / 'bin/ninja').chmod(0o755)
                if row['kind'] == 'meson-bootstrap':
                    install_meson(source, prefix)
                for item in row.get('copy_trees', []):
                    origin, destination = source / item['source'], prefix / item['destination']
                    if not origin.resolve().is_relative_to(source.resolve()):
                        raise ValueError(f'Data source: expected inside={str(source)!r}; actual={str(origin.resolve())!r}')
                    shutil.copytree(origin, destination)
                    event(out, component=current, state='DATA_INSTALLED', source=item['source'],
                          destination=item['destination'])
                if current == 'pkgconf' and not (prefix / 'bin/pkg-config').exists():
                    (prefix / 'bin/pkg-config').symlink_to('pkgconf')
                phase = 'OUTPUTS'
                if not ((_repro_check_68_0 := all(((prefix / x).is_file() for x in row['outputs'])))):
                    raise AssertionError(_check_message("all((prefix / x).is_file() for x in row['outputs'])", {"all(((prefix / x).is_file() for x in row['outputs']))": locals().get('_repro_check_68_0', 'NOT_EVALUATED')}, 'Required output missing'))
                probes = []
                if row.get('probe'):
                    value = output([str(prefix / row['probe'][0]), *row['probe'][1:]], env=env)
                    if not ((_repro_check_69_0 := re.search('(?<![\\d.])' + re.escape(row['version']) + '(?![\\d.])', value))):
                        raise AssertionError(_check_message("re.search(r'(?<![\\d.])' + re.escape(row['version']) + r'(?![\\d.])', value)", {"re.search('(?<![\\\\d.])' + re.escape(row['version']) + '(?![\\\\d.])', value)": locals().get('_repro_check_69_0', 'NOT_EVALUATED')}, 'validation failed'))
                    probes.append(dict(kind='tool_version', output=value))
                for path in row['outputs']:
                    if path.endswith('.pc'):
                        value = output([str(prefix / 'bin/pkg-config'), '--modversion', Path(path).stem], env=env)
                        if row.get('pkg_config_version'):
                            if not ((_repro_check_70_0 := value) == (_repro_check_70_1 := row['pkg_config_version'])):
                                raise AssertionError(_check_message("value == row['pkg_config_version']", {'value': locals().get('_repro_check_70_0', 'NOT_EVALUATED'), "row['pkg_config_version']": locals().get('_repro_check_70_1', 'NOT_EVALUATED')}, 'pkg-config selected wrong component version'))
                        probes.append(dict(kind='pkg_config_version', module=Path(path).stem, output=value))
                if current == 'libvpx':
                    phase = 'DYLIB_ID'
                    probes.append(libvpx_install_name_probe(prefix, env, out, deadline, command))
                if row.get('gst_plugins'):
                    phase = 'PLUGIN_LOAD'
                    probes.extend(gst_plugin_probes(row, source, prefix, env, out, deadline))
                if row.get('flex_libfl_probe'):
                    phase = 'FLEX_LIBFL_PROBE'
                    probes.append(flex_libfl_probe(prefix, env, out, deadline))
                phase = 'LICENSES'
                copied = licenses(source, prefix, current)
                receipt['components'][row.get('wine_requirement', current)] = dict(version=row['version'], build_rc=0,
                    recipe_sha256=digest((json.dumps(row, sort_keys=True) + driver_sha + lock_sha).encode()),
                    sources=[dict(url=row['url'], sha256=row['sha256'])],
                    deployment_target=target, outputs=row['outputs'], probes=probes, licenses=copied,
                    source_ownership=ownership,
                    evidence='PRESENT', source_pin_metadata=row['metadata'])
                event(out, component=current, state='COMPONENT_BUILT', output_files=row['outputs'])
                (out / 'dependency-manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
            except Exception as error:
                failure = dict(component=current, phase=phase, error=str(error), state='FAILED',
                               evidence='DROPPED' if 'LOG_LIMIT_DROPPED' in str(error) else 'PRESENT_BOUNDED')
                failure['command_evidence'] = failure_evidence.latest(out, component=current)
                if current == 'gnutls' and source is None:
                    failure['test_evidence'] = dict(state='NOT_ENABLED', reason='SOURCE_NOT_AVAILABLE')
                if current == 'gnutls' and source is not None:
                    try:
                        captured = preserve_gnutls_tests(source, out, current)
                        failure['test_evidence'] = dict(state=captured['state'], files=len(captured['files']),
                                                        bytes=captured['bytes'], path='gnutls-test-evidence.json')
                    except Exception as capture_error:
                        failure['test_evidence'] = dict(state='FAILED', error=str(capture_error))
                receipt['failures'].append(failure)
                receipt.setdefault('first_failure', failure)
                receipt['component_states'][current] = failure
                event(out, component=current, state='FAILED', phase=phase, error=str(error))
                (out / 'dependency-manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
                continue
            completed_names.add(current)
            receipt['component_states'][current] = dict(component=current, state='BUILT', evidence='PRESENT')

        phase = 'INVENTORY'
        receipt['files'] = inventory(prefix)
        complete = not receipt['failures'] and not receipt['skipped_components']
        receipt.update(source_built=complete, status=('PARTIAL_DEPENDENCIES_BUILT_NOT_WINE_READY' if complete else 'PARTIAL_DEPENDENCIES_FAILED_NOT_WINE_READY'))
    except Exception as error:
        fatal = dict(component=current, phase=phase, error=str(error))
        fatal['command_evidence'] = failure_evidence.latest(out, component=current)
        receipt.setdefault('first_failure', fatal)
        receipt.update(status='FAILED', fatal_failure=fatal, raw_evidence='PRESENT_BOUNDED')
        event(out, component=current, state='FAILED', phase=phase, error=str(error))
        raise
    finally:
        receipt['install_skipped'] = sum('install skipped' in line.lower()
            for path in out.glob('*.log') for line in path.read_text(errors='replace').splitlines())
        (out / 'dependency-manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
        (out / 'RESULT.json').write_text(json.dumps(dict(status=receipt['status'],
            built_components=len(receipt['components']), requested_components=lock['requested_components'],
            missing_wine_recipe_components=lock['remaining_wine_required'],
            missing_wine_components=[name for name in lock['wine_required'] if name not in receipt['components']],
            failed_components=receipt['failures'], skipped_components=receipt['skipped_components'],
            component_states=receipt['component_states'],
            first_failure=receipt.get('first_failure'), install_skipped=receipt['install_skipped'],
            wine_ready=False, comparison='NOT_ENABLED', stands='NOT_ENABLED'), indent=2) + '\n')
    if not ((_repro_check_71_0 := receipt['install_skipped']) == (_repro_check_71_1 := 0)):
        raise AssertionError(_check_message("receipt['install_skipped'] == 0", {"receipt['install_skipped']": locals().get('_repro_check_71_0', 'NOT_EVALUATED'), '0': locals().get('_repro_check_71_1', 'NOT_EVALUATED')}, 'install skipped found'))
    print(json.dumps(dict(status=receipt['status'], built_components=len(receipt['components']),
        requested_components=lock['requested_components'],
        failures=[row['component'] for row in receipt['failures']],
        skipped=[row['component'] for row in receipt['skipped_components']], wine_ready=False)))
    if receipt['failures'] or receipt['skipped_components']:
        raise RuntimeError(f"Dependency batch incomplete: expected={lock['requested_components']} built; actual={len(receipt['components'])}, failures={len(receipt['failures'])}, skipped={len(receipt['skipped_components'])}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-inputs', action='store_true')
    mode.add_argument('--build', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--minutes', type=int, default=90)
    parser.add_argument('--profile', choices=['github', 'xcode-cloud'], default='github')
    args = parser.parse_args()
    locked = read_lock()
    source_download.read_pins()
    source_download.read_routes()
    if args.profile == 'xcode-cloud':
        locked['toolchain'] = dict(json.loads((HERE / 'xcode-cloud.lock.json').read_text()),
                                   deployment_target=locked['toolchain']['deployment_target'])
    if args.check_inputs:
        print(json.dumps(dict(status='INPUTS_OK_NOT_BUILT', components=len(locked['components']),
                              missing_wine_components=locked['remaining_wine_required'])))
    else:
        if not ((_repro_check_72_0 := args.work) and (_repro_check_72_1 := 1) <= (_repro_check_72_2 := args.jobs) <= (_repro_check_72_3 := 16) and ((_repro_check_72_4 := 1) <= (_repro_check_72_5 := args.minutes) <= (_repro_check_72_6 := 100))):
            raise AssertionError(_check_message('args.work and 1 <= args.jobs <= 16 and 1 <= args.minutes <= 100', {'args.work': locals().get('_repro_check_72_0', 'NOT_EVALUATED'), '1': locals().get('_repro_check_72_1', 'NOT_EVALUATED'), 'args.jobs': locals().get('_repro_check_72_2', 'NOT_EVALUATED'), '16': locals().get('_repro_check_72_3', 'NOT_EVALUATED'), '1': locals().get('_repro_check_72_4', 'NOT_EVALUATED'), 'args.minutes': locals().get('_repro_check_72_5', 'NOT_EVALUATED'), '100': locals().get('_repro_check_72_6', 'NOT_EVALUATED')}, 'validation failed'))
        build(args, locked)

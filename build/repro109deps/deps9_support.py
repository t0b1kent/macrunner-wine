"""SDK metadata and failed upstream-test evidence; no local source fetching."""
import hashlib
import json
from pathlib import Path
import re
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sdk_zlib_metadata(sdk, prefix, out):
    sdk = sdk.resolve()
    header, library = sdk / 'usr/include/zlib.h', sdk / 'usr/lib/libz.tbd'
    for path in [header, library]:
        if not path.is_file() or not path.resolve().is_relative_to(sdk):
            raise ValueError('SDK zlib: expected selected SDK file; actual=' + str(path))
    match = re.search(r'^#\s*define\s+ZLIB_VERSION\s+"([0-9]+\.[0-9]+(?:\.[0-9]+)*)"',
                      header.read_text(), re.M)
    if not match:
        raise ValueError('SDK zlib: expected literal ZLIB_VERSION; actual=NOT_FOUND')
    pc = prefix / 'lib/pkgconfig/zlib.pc'
    if pc.exists():
        raise ValueError('SDK zlib: expected fresh metadata; actual=existing ' + str(pc))
    value = (f'prefix={sdk}/usr\nexec_prefix=${{prefix}}\nlibdir=${{prefix}}/lib\n'
             'includedir=${prefix}/include\n\nName: zlib\n'
             'Description: zlib from the selected Apple SDK (platform dependency)\n'
             f'Version: {match[1]}\nLibs: -L${{libdir}} -lz\nCflags: -I${{includedir}}\n')
    pc.write_text(value)
    receipt = dict(state='PRESENT', owner='SELECTED_APPLE_SDK_NOT_SOURCE_BUILT',
                   header_version=match[1], sdk=str(sdk),
                   inputs=[dict(path=str(path), sha256=sha(path)) for path in [header, library]],
                   pkg_config=dict(path=str(pc), sha256=sha(pc)), runtime_probe='NOT_ENABLED')
    (out / 'sdk-zlib-metadata.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def probe_sdk_zlib(prefix, env, out, deadline, command):
    source = out / 'sdk-zlib-probe.c'
    source.write_text('#include <zlib.h>\n#include <stdio.h>\n#include <string.h>\n'
                      'int main(void) {\n'
                      ' const Bytef input[] = "MacRunner SDK zlib probe";\n'
                      ' Bytef packed[128], restored[128];\n'
                      ' uLongf packed_n = sizeof(packed), restored_n = sizeof(restored);\n'
                      ' if (compress(packed, &packed_n, input, sizeof(input)) != Z_OK) return 1;\n'
                      ' if (uncompress(restored, &restored_n, packed, packed_n) != Z_OK) return 2;\n'
                      ' if (restored_n != sizeof(input) || memcmp(input, restored, sizeof(input))) return 3;\n'
                      ' printf("SDK_ZLIB_OK header=%s runtime=%s\\n", ZLIB_VERSION, zlibVersion());\n'
                      ' return 0;\n}\n')
    binary = out / 'sdk-zlib-probe'
    command([env['CC'], '-arch', 'arm64', '-isysroot', env['SDKROOT'],
             '-mmacosx-version-min=' + env['MACOSX_DEPLOYMENT_TARGET'], str(source), '-lz',
             '-o', str(binary)], out, env, out / 'sdk-zlib-probe-compile.log',
            out, 'sdk-zlib', deadline)
    command([str(binary)], out, env, out / 'sdk-zlib-probe-run.log', out, 'sdk-zlib', deadline)
    text = (out / 'sdk-zlib-probe-run.log').read_text()
    match = re.search(r'^SDK_ZLIB_OK header=(\S+) runtime=(\S+)$', text, re.M)
    if not match:
        raise ValueError('SDK zlib probe: expected round-trip marker; actual=NOT_FOUND')
    receipt = json.loads((out / 'sdk-zlib-metadata.json').read_text())
    if match[1] != receipt['header_version']:
        raise ValueError('SDK zlib probe: expected selected header version; actual=' + match[1])
    receipt['runtime_probe'] = dict(state='PRESENT', header_version=match[1], runtime_version=match[2],
                                   source_sha256=sha(source), binary_sha256=sha(binary),
                                   log_sha256=sha(out / 'sdk-zlib-probe-run.log'))
    (out / 'sdk-zlib-metadata.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt['runtime_probe']


def preserve_gnutls_tests(source, out, component, max_bytes=32*1024*1024, max_files=2048):
    """Copy raw test logs before source-work cleanup; refusal never replaces the build error."""
    if component != 'gnutls':
        return None
    root = source.resolve()
    tests = source / 'tests'
    report = dict(state='EMPTY', files=[], omitted=[], bytes=0, max_bytes=max_bytes,
                  max_files=max_files, purpose='FAILED_UPSTREAM_TEST_DIAGNOSIS_NOT_TEST_WAIVER')
    target = out / 'gnutls-test-evidence'
    target.mkdir()
    if not tests.is_dir():
        report.update(state='FAILED', error='tests directory absent')
    else:
        priority = [tests/'test-suite.log', tests/'gnutls-cli-debug.log', tests/'gnutls-cli-debug.trs',
                    tests/'gnutls-cli-debug.sh', tests/'scripts/common.sh']
        priority += sorted(tests.glob('repro109-port-*.log'))
        candidates = [*priority, *sorted(p for p in tests.rglob('*') if p.suffix in {'.log', '.trs'})]
        seen = set()
        for path in candidates:
            name = str(path.relative_to(source))
            if name in seen:
                continue
            seen.add(name)
            try:
                if not path.is_file():
                    if path in priority:
                        report['omitted'].append(dict(path=name, state='EMPTY'))
                    continue
                if not path.resolve().is_relative_to(root):
                    raise ValueError('file escapes source root')
                size = path.stat().st_size
                if len(report['files']) >= max_files or report['bytes'] + size > max_bytes:
                    report['omitted'].append(dict(path=name, bytes=size, state='DROPPED', reason='CAP'))
                    continue
                destination = target / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                expected, actual = sha(path), sha(destination)
                if expected != actual:
                    raise ValueError('raw copy SHA differs')
                report['files'].append(dict(path=name, bytes=size, sha256=actual, state='PRESENT'))
                report['bytes'] += size
            except (OSError, ValueError) as error:
                report['omitted'].append(dict(path=name, state='FAILED', error=str(error)))
        report['state'] = ('DROPPED' if any(x['state']=='DROPPED' for x in report['omitted']) else
                           'FAILED' if any(x['state']=='FAILED' for x in report['omitted']) else
                           'PRESENT' if report['files'] else 'EMPTY')
    (out / 'gnutls-test-evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    return report

"""Small archive-bound source transforms; called only by the cloud build driver."""
import difflib
import hashlib
import re


def lame_exports(data):
    lines = data.splitlines(keepends=True)
    count = sum(line.rstrip(b'\r\n') == b'lame_init_old' for line in lines)
    if count != 1:
        raise ValueError(f'LAME obsolete export: expected=1 exact entry; actual={count}')
    return b''.join(line for line in lines if line.rstrip(b'\r\n') != b'lame_init_old'), count


def gnutls_test_links(data):
    # gl/libgnu.la contains rpl_free; libgnutls deliberately exports public APIs only.
    # Cover the common LDADD and explicit sibling target LDADD assignments.
    lines = data.decode('utf-8').splitlines(keepends=True)
    result, count, index = [], 0, 0
    while index < len(lines):
        group = [lines[index]]
        index += 1
        if re.match(r'^(?:[A-Za-z0-9_]+_)?LDADD\s*=', group[0]):
            while group[-1].rstrip('\r\n').endswith('\\') and index < len(lines):
                group.append(lines[index])
                index += 1
            text = ''.join(group)
            if 'libgnutls.la' in text and '/gl/libgnu.la' not in text:
                last = group[-1]
                ending = '\r\n' if last.endswith('\r\n') else ('\n' if last.endswith('\n') else '')
                body = last[:-len(ending)] if ending else last
                group[-1] = body + ' $(top_builddir)/gl/libgnu.la' + ending
                count += 1
        result.extend(group)
    if count < 1:
        raise ValueError(f'GnuTLS test link inputs: expected>=1 libgnutls LDADD assignment; actual={count}')
    return ''.join(result).encode('utf-8'), count


def gnutls_port_observation(data):
    expected = 'e226f6018152a846f0bb5b5d67bde9b29ce135edef5bae93d91f590748dead7e'
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('GnuTLS common.sh byte identity differs from pinned 3.8.13 archive')
    before = b'\t$PFCMD -anl|grep -v ::|grep "[\\:\\.]$PORT"|grep LISTEN >/dev/null 2>&1\n'
    after = b'''\tif test "$(uname -s)" = Darwin && test -n "$REPRO109_PORT_PYTHON" && test -n "$REPRO109_PORT_PROBE"; then
\t\t"$REPRO109_PORT_PYTHON" -B -I "$REPRO109_PORT_PROBE" --check-listening --port "$PORT" --owned-pid "${PID:-${TLS_SERVER_PID:-${OCSP_PID:-0}}}" >/dev/null 2>&1
\telse
''' + before + b'''\tfi
\trepro109_port_rc=$?
\tif test "$repro109_port_rc" != 0 && test "${repro109_port_observed:-0}" != 1; then
\t\trepro109_port_observed=1
\t\tif test -n "$REPRO109_PORT_PYTHON" && test -n "$REPRO109_PORT_PROBE"; then
\t\t\t"$REPRO109_PORT_PYTHON" -B -I "$REPRO109_PORT_PROBE" --port "$PORT" --owned-pid "${PID:-${TLS_SERVER_PID:-${OCSP_PID:-0}}}" --output "$abs_top_builddir/tests/repro109-port-$$.log" || :
\t\tfi
\tfi
\treturn "$repro109_port_rc"
'''
    if data.count(before) != 1:
        raise ValueError('GnuTLS port-finder observation anchor is not unique')
    fault = b'\t\techo "Server $PORT did not come up"\n'
    if data.count(fault) != 1:
        raise ValueError('GnuTLS confirmed port-wait failure anchor is not unique')
    capture = fault + b'''\t\tif test -n "$REPRO109_PORT_PYTHON" && test -n "$REPRO109_PORT_PROBE"; then
\t\t\t"$REPRO109_PORT_PYTHON" -B -I "$REPRO109_PORT_PROBE" --port "$PORT" --owned-pid "$PID" --output "$abs_top_builddir/tests/repro109-port-final-$$.log" || :
\t\tfi
'''
    return data.replace(before, after).replace(fault, capture), 2


def libvpx_darwin_install_name(data):
    # dl_template is the Darwin shared-library rule. A bare output basename
    # becomes LC_ID_DYLIB and propagates into every downstream codec consumer.
    before = b'\t$(qexec)$$(LD) -dynamiclib $$(LDFLAGS) \\\n'
    after = before + b'        -Wl,-install_name,@rpath/$$(notdir $$@) \\\n'
    count = data.count(before)
    if count != 1 or b'-Wl,-install_name,@rpath/$$(notdir $$@)' in data:
        raise ValueError(f'libvpx Darwin shared rule: expected=1 unpatched; actual={count}')
    return data.replace(before, after, 1), count


def apply_source_fixes(row, source, out, emit):
    recipes = {
        'lame': ('3.100', 'include/libmp3lame.sym', lame_exports),
        'gnutls': ('3.8.13', 'tests/Makefile.in', gnutls_test_links),
        'libvpx': ('1.16.0', 'build/make/Makefile', libvpx_darwin_install_name),
    }
    if row['name'] not in recipes:
        return
    version, relative, transform = recipes[row['name']]
    if row['version'] != version:
        raise ValueError(f'Source transform version: expected={version}; actual={row["version"]}')
    path = source / relative
    if not path.is_file() or not path.resolve().is_relative_to(source.resolve()):
        raise ValueError(f'Source transform input: expected=owned file {relative}; actual={path}')
    before = path.read_bytes()
    if row['name'] == 'libvpx' and hashlib.sha256(before).hexdigest() != 'b7554da31a575b282c855e44ccd25a772315ba4b10d7de0ab62f9a07dd9ebb27':
        raise ValueError('libvpx 1.16.0 Darwin Makefile fingerprint differs')
    if len(before) > 8 * 1024 * 1024:
        raise ValueError(f'Source transform size: expected<=8388608; actual={len(before)}')
    after, count = transform(before)
    name = row['name'] + '-source-fix'
    (out / (name + '-before.raw')).write_bytes(before)
    (out / (name + '-after.raw')).write_bytes(after)
    patch = ''.join(difflib.unified_diff(before.decode().splitlines(keepends=True),
                                       after.decode().splitlines(keepends=True),
                                       fromfile=relative, tofile=relative)).encode()
    (out / (name + '.patch')).write_bytes(patch)
    path.write_bytes(after)
    emit(out, component=row['name'], state='SOURCE_TRANSFORM', path=relative,
         replacements=count, input_sha256=hashlib.sha256(before).hexdigest(),
         output_sha256=hashlib.sha256(after).hexdigest(),
         patch_sha256=hashlib.sha256(patch).hexdigest(), raw_prefix=name)
    if row['name'] == 'gnutls':
        path = source/'tests/scripts/common.sh'
        if not path.is_file() or not path.resolve().is_relative_to(source.resolve()):
            raise ValueError('GnuTLS common.sh must be an owned source file')
        before = path.read_bytes()
        after, count = gnutls_port_observation(before)
        name = 'gnutls-port-observation'
        (out/(name+'-before.raw')).write_bytes(before)
        (out/(name+'-after.raw')).write_bytes(after)
        patch = ''.join(difflib.unified_diff(before.decode().splitlines(keepends=True),
                                            after.decode().splitlines(keepends=True),
                                            fromfile='tests/scripts/common.sh', tofile='tests/scripts/common.sh')).encode()
        (out/(name+'.patch')).write_bytes(patch)
        path.write_bytes(after)
        emit(out, component='gnutls', state='SOURCE_TRANSFORM', path='tests/scripts/common.sh',
             replacements=count, purpose='DARWIN_TCP_READINESS_NO_TEST_WAIVER',
             input_sha256=hashlib.sha256(before).hexdigest(), output_sha256=hashlib.sha256(after).hexdigest(),
             patch_sha256=hashlib.sha256(patch).hexdigest(), raw_prefix=name)

"""Bounded byte-exact command failure fields for every existing cloud phase."""
import base64
import hashlib
import json
from pathlib import Path
import re
import time

TAIL_LINES = 250
TAIL_BYTES = 64 * 1024
ERROR_LINES = 20
ERROR_BYTES = 32 * 1024
LINE_BYTES = 8192
SCAN_BYTES = 64 * 1024**2
MANIFEST_BYTES = 1024 * 1024
ERROR = re.compile(rb'error:|FAILED:|(?:^|\s)ld:')


def window(raw, offset):
    return dict(offset=offset, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                raw_base64=base64.b64encode(raw).decode('ascii'), text=raw.decode('utf-8', errors='replace'))


def inspect_log(path):
    path = Path(path)
    if path.is_symlink(): return dict(state='FAILED', reason='LOG_SYMLINK_REFUSED')
    if not path.is_file(): return dict(state='NOT_PRESENT', path=path.name)
    before = path.stat()
    size = before.st_size
    with path.open('rb') as stream:
        stream.seek(max(0, size - TAIL_BYTES))
        tail = b''.join(stream.read(TAIL_BYTES).splitlines(keepends=True)[-TAIL_LINES:])
        stream.seek(0)
        selected, scanned, number, used, matches = [], 0, 0, 0, 0
        dropped_line = False
        complete = True
        digest = hashlib.sha256()
        while scanned < min(size, SCAN_BYTES):
            offset = scanned
            line = stream.readline(min(LINE_BYTES + 1, SCAN_BYTES - scanned))
            if not line: break
            scanned += len(line)
            digest.update(line)
            number += 1
            long_line = len(line) > LINE_BYTES and not line.endswith(b'\n')
            if ERROR.search(line):
                matches += 1
                if len(selected) < ERROR_LINES and used < ERROR_BYTES:
                    raw = line[:min(LINE_BYTES, ERROR_BYTES - used)]
                    selected.append(dict(line=number, truncated=len(raw) != len(line), **window(raw, offset)))
                    used += len(raw)
            if long_line:
                dropped_line = True
                while scanned < min(size, SCAN_BYTES) and not line.endswith(b'\n'):
                    line = stream.readline(min(LINE_BYTES + 1, SCAN_BYTES - scanned))
                    if not line: break
                    scanned += len(line)
                    digest.update(line)
        complete = scanned == size and not dropped_line
    after = path.stat()
    unchanged = (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns)
    return dict(state=('PRESENT' if size else 'EMPTY') if unchanged else 'FAILED', path=path.name,
                log_bytes=size, log_sha256=digest.hexdigest() if scanned == size and unchanged else 'NOT_MEASURED',
                tail=window(tail, size - len(tail)), tail_lines=len(tail.splitlines()),
                tail_selection_dropped=size > len(tail), first_error_lines=selected,
                error_matches_in_scanned_bytes=matches, errors_not_selected=matches - len(selected),
                errors_state='PRESENT' if selected else 'EMPTY' if complete else 'DROPPED',
                error_scan_state='COMPLETE' if complete else 'DROPPED', error_scan_bytes=scanned,
                source_unchanged=unchanged, caps=dict(tail_lines=TAIL_LINES, tail_bytes=TAIL_BYTES,
                    first_error_lines=ERROR_LINES, error_bytes=ERROR_BYTES, scan_bytes=SCAN_BYTES))


def capture(log, out, component, *, rc=None, reason=None):
    try:
        evidence = inspect_log(log)
    except Exception as error:
        evidence = dict(state='FAILED', reason=type(error).__name__, path=Path(log).name)
    row = dict(schema=1, component=component, rc=rc, reason=reason,
               monotonic=time.monotonic(), log=evidence)
    try:
        (Path(out) / 'COMMAND-FAILURE.json').write_text(json.dumps(row, sort_keys=True, indent=2) + '\n')
    except Exception:
        # Preserve the original command refusal; this never changes its rc.
        return dict(state='FAILED', reason='FAILURE_EVIDENCE_WRITE_FAILED', command=row)
    return row


def latest(out, *, since=None, component=None):
    path = Path(out) / 'COMMAND-FAILURE.json'
    if path.is_symlink(): return dict(state='FAILED', reason='FAILURE_MANIFEST_SYMLINK_REFUSED')
    if not path.is_file(): return dict(state='NOT_ENABLED', reason='NO_COMMAND_FAILURE_CAPTURE')
    try:
        if path.stat().st_size > MANIFEST_BYTES: raise ValueError('Failure manifest byte cap')
        row = json.loads(path.read_bytes())
        if not isinstance(row, dict) or not isinstance(row.get('log'), dict): raise ValueError('Failure manifest shape')
        if since is not None and row.get('monotonic', -1) < since:
            return dict(state='NOT_ENABLED', reason='FAILURE_PREDATES_LIVE_SESSION')
        if component is not None:
            actual, expected = str(row.get('component', '')), str(component)
            if actual != expected and not any(actual.startswith(expected + mark) for mark in (':', '-', '/')):
                return dict(state='NOT_ENABLED', reason='OTHER_COMPONENT_FAILURE')
        return row
    except Exception as error:
        return dict(state='FAILED', reason=type(error).__name__)

#!/usr/bin/env python3
"""Upstream test-suite policy for the dependency builds of the 1.1.0 candidate (REPRO-110).

Why: the first full Wine run of the candidate (38500992506) spent 77 minutes and then stopped at gnutls: one test of its own
suite (gnutls-cli-rawpk.sh) found its random server port taken (bind(): Address already in use) while the same suite had
passed in the 1.0.9 run (37616083395). One flaky test must not cost two hours, and it must not be hidden either.

Rule (POLICY): a dependency whose recipe runs `make check`
  1. keeps the suite's own results in the report even when everything passes: test-suite.log files, gzipped, bounded, with
     SHA-256, and the pass/skip/fail counts read from the .trs files;
  2. when the suite fails, the tests that failed are run again, once, serially (`make recheck -j1`: automake runs only the
     failed tests). A test that fails in the first run and passes on recheck is recorded as PASSED_ON_RECHECK with both logs;
  3. a test that still fails fails the component, unless the pair (component, test) is named in
     upstream-test-allowlist.lock.json with a reason and evidence; those are recorded as ALLOWLISTED. The list is empty.
  4. a failure with no identified failed test (a build error, a time limit) is never rechecked and always fails.
Everything is written to <reports>/upstream-tests.json; nothing here weakens the build outputs, only the verdict on tests.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

POLICY = 'RECHECK_FAILED_ONCE_SERIALLY_THEN_NAMED_ALLOWLIST'
REPORT = 'upstream-tests.json'
MAX_FILES = 8
MAX_GZ_BYTES = 6 * 1024 ** 2
MAX_SOURCE_BYTES = 64 * 1024 ** 2
GOOD = {'PASS', 'SKIP', 'XFAIL'}


def read_allowlist(path):
    data = json.loads(Path(path).read_bytes())
    if data.get('schema') != 1 or not isinstance(data.get('allow'), list):
        raise ValueError('Upstream test allowlist differs')
    seen = {}
    for row in data['allow']:
        for key in ('component', 'test', 'reason', 'evidence'):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError('Allowlist entry needs a component, a test, a reason and evidence')
        pair = (row['component'], row['test'])
        if pair in seen:
            raise ValueError('Duplicate allowlist entry')
        seen[pair] = row
    return seen


def trs_results(cwd, depth=4):
    """Map test name -> result for every .trs file below cwd."""
    base, found = Path(cwd), {}
    for root, dirs, files in os.walk(base):
        if len(Path(root).relative_to(base).parts) >= depth:
            dirs[:] = []
        for name in files:
            if name.endswith('.trs'):
                text = (Path(root) / name).read_text(errors='replace')
                result = next((l.split(':', 2)[2].strip() for l in text.splitlines() if l.startswith(':test-result:')), 'UNKNOWN')
                found[str((Path(root) / name).relative_to(base))[:-4]] = result
    return found


def failing_tests(cwd):
    return sorted(name for name, result in trs_results(cwd).items() if result not in GOOD)


def counts(cwd):
    result = {}
    for value in trs_results(cwd).values():
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


def collect(cwd, out, component, phase):
    """Gzip the suite logs found below cwd into the reports directory, bounded."""
    base, rows, total = Path(cwd), [], 0
    for root, dirs, files in os.walk(base):
        if len(Path(root).relative_to(base).parts) >= 4:
            dirs[:] = []
        if 'test-suite.log' in files and len(rows) < MAX_FILES:
            path = Path(root) / 'test-suite.log'
            size = path.stat().st_size
            if size > MAX_SOURCE_BYTES:
                rows.append(dict(path=str(path.relative_to(base)), bytes=size, state='DROPPED_OVER_SOURCE_CAP'))
                continue
            data = path.read_bytes()
            target = Path(out) / ('%s-upstream-%s-%d.log.gz' % (component, phase, len(rows)))
            packed = gzip.compress(data, 9, mtime=0)
            if total + len(packed) > MAX_GZ_BYTES:
                rows.append(dict(path=str(path.relative_to(base)), bytes=size, state='DROPPED_OVER_REPORT_CAP'))
                continue
            target.write_bytes(packed)
            total += len(packed)
            rows.append(dict(path=str(path.relative_to(base)), bytes=size, sha256=hashlib.sha256(data).hexdigest(),
                             report_file=target.name, gz_bytes=len(packed), state='PRESENT'))
    return rows


def default_listeners(out, component):
    """Who listens on TCP right now: the answer to 'Address already in use' that the failed run could not give."""
    text = []
    for argv in (['/usr/sbin/lsof', '-nP', '-iTCP', '-sTCP:LISTEN'], ['/bin/ps', '-Ao', 'pid,ppid,etime,args']):
        try:
            done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
            text.append('$ ' + ' '.join(argv) + '  rc=%d\n' % done.returncode + done.stdout[:48 * 1024])
        except Exception as error:  # evidence only
            text.append('$ ' + ' '.join(argv) + '  ERROR ' + type(error).__name__ + '\n')
    target = Path(out) / (component + '-listeners-after-failure.txt')
    target.write_text('\n'.join(text)[:96 * 1024])
    return target.name


def record(out, entry):
    path = Path(out) / REPORT
    data = json.loads(path.read_bytes()) if path.is_file() else dict(schema=1, policy=POLICY, components=[])
    data['components'].append(entry)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    tmp.replace(path)


def summary(out):
    path = Path(out) / REPORT
    if not path.is_file():
        return dict(policy=POLICY, components=[])
    data = json.loads(path.read_bytes())
    return dict(policy=POLICY, components=[dict(component=c['component'], outcome=c['outcome'], counts=c.get('counts'),
                first_failed=c.get('first_failed', []), allowlisted=[a['test'] for a in c.get('allowlisted', [])])
                for c in data['components']])


def install(dep, allowlist_path, listeners=default_listeners):
    """Wrap dep.command so that `make check` steps follow the policy. Other commands pass through untouched."""
    original = dep.command
    allow = read_allowlist(allowlist_path)

    def wrapped(argv, cwd, env, log, out, component, deadline, timeout=1800):
        if list(argv[:2]) != ['make', 'check']:
            return original(argv, cwd, env, log, out, component, deadline, timeout)
        entry = dict(component=component, command=list(argv), started=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        try:
            original(argv, cwd, env, log, out, component, deadline, timeout)
        except AssertionError as first:
            entry.update(first_run='FAILED', first_logs=collect(cwd, out, component, 'first'),
                         first_failed=failing_tests(cwd), counts=counts(cwd), listeners=listeners(out, component))
            hard = any(word in str(first) for word in ('TIMEOUT', 'LOG_LIMIT', 'SPAWN_ERROR'))
            if hard or not entry['first_failed']:
                entry['outcome'] = 'FAILED_NO_TEST_TO_RECHECK'
                record(out, entry)
                raise
            extra = [a for a in argv[2:] if not a.startswith('-j')]
            recheck_log = Path(log).with_name(Path(log).stem + '-recheck.log')
            try:
                original(['make', 'recheck', '-j1', *extra], cwd, env, recheck_log, out, component + '-recheck', deadline, timeout)
            except AssertionError:
                still = failing_tests(cwd)
                entry.update(recheck_run='FAILED', recheck_logs=collect(cwd, out, component, 'recheck'),
                             recheck_failed=still, counts=counts(cwd))
                named = [allow.get((component, test)) for test in still]
                if still and all(named):
                    entry.update(outcome='ALLOWLISTED', allowlisted=[dict(test=t, reason=r['reason'], evidence=r['evidence'])
                                                                      for t, r in zip(still, named)])
                    record(out, entry)
                    return
                entry['outcome'] = 'FAILED_AFTER_RECHECK'
                record(out, entry)
                raise first
            entry.update(recheck_run='PASSED', recheck_logs=collect(cwd, out, component, 'recheck'), counts=counts(cwd),
                         outcome='PASSED_ON_RECHECK')
            record(out, entry)
            return
        entry.update(first_run='PASSED', first_logs=collect(cwd, out, component, 'first'), counts=counts(cwd), outcome='PASSED')
        record(out, entry)

    dep.command = wrapped
    return original

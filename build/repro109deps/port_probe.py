"""Cloud-only observation of the failed GnuTLS port finder; never waives a test."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time


def readiness(port, connector=None):
    """Bounded connection to the owned test's loopback port; not a TLS test."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Owned test port refused')
    connector = socket.create_connection if connector is None else connector
    result = dict(purpose='OWNED_LOOPBACK_TCP_READINESS_NOT_TLS_ACCEPTANCE', port=port,
                  timeout_seconds=0.5, utc=datetime.now(timezone.utc).isoformat(),
                  monotonic_start_ns=time.monotonic_ns())
    try:
        with connector(('127.0.0.1', port), timeout=0.5):
            result.update(state='PRESENT', rc=0)
    except socket.timeout:
        result.update(state='FAILED', rc=1, reason='CONNECT_TIMEOUT')
    except OSError as error:
        result.update(state='EMPTY', rc=1, reason='CONNECT_NOT_READY', errno=error.errno)
    result['monotonic_end_ns'] = time.monotonic_ns()
    return result


def owned_listener(port, pid, run=subprocess.run):
    """Passive native query: never connect to or consume the test protocol."""
    if type(port) is not int or not 1 <= port <= 65535 or type(pid) is not int or pid <= 1:
        raise ValueError('Owned positive PID and TCP port required')
    result = dict(purpose='PASSIVE_OWNED_PID_TCP_LISTENER_NOT_TLS_ACCEPTANCE',
                  pid=pid, port=port, rc=1, utc=datetime.now(timezone.utc).isoformat(),
                  monotonic_start_ns=time.monotonic_ns())
    try:
        child = run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(pid),
                     '-iTCP:' + str(port), '-sTCP:LISTEN', '-F', 'pfn'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL':'C'}, timeout=2)
        result.update(command_rc=child.returncode, stdout_bytes=len(child.stdout),
                      stdout_sha256=hashlib.sha256(child.stdout).hexdigest(),
                      stderr_bytes=len(child.stderr), stderr_sha256=hashlib.sha256(child.stderr).hexdigest())
        if len(child.stdout)>65536 or len(child.stderr)>8192:
            result.update(state='DROPPED', reason='OUTPUT_CAP')
        elif child.returncode not in (0, 1):
            result.update(state='FAILED', reason='LSOF_FAILED', stderr_hex=child.stderr.hex())
        else:
            lines = child.stdout.splitlines()
            same_pid = bool(lines) and lines[0] == ('p'+str(pid)).encode() and sum(x.startswith(b'p') for x in lines)==1
            endpoint = re.compile(rb'^n[^\n]*:' + str(port).encode() + rb'(?: \(LISTEN\))?$')
            matched = same_pid and any(endpoint.fullmatch(line) for line in lines)
            result.update(state='PRESENT' if matched and child.returncode==0 else 'EMPTY',
                          rc=0 if matched and child.returncode==0 else 1,
                          raw_stdout_hex=child.stdout.hex(), raw_stderr_hex=child.stderr.hex())
    except subprocess.TimeoutExpired:
        result.update(state='FAILED', reason='TIMEOUT')
    except OSError:
        result.update(state='FAILED', reason='NATIVE_PROCESS_START_FAILED')
    result['monotonic_end_ns']=time.monotonic_ns()
    return result


def observe(finder, port, run=subprocess.run, *, connect=False):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Owned test port refused')
    executable = shutil.which(finder)
    if executable not in {'/usr/sbin/netstat', '/usr/bin/netstat', '/sbin/ss', '/usr/sbin/ss'}:
        return dict(state='FAILED', reason='NATIVE_PORT_FINDER_NOT_RESOLVED',
                    finder_name=Path(finder).name, port=port)
    result = dict(state='PRESENT', purpose='PORT_WAIT_DIAGNOSIS_NOT_TEST_WAIVER',
                  finder=executable, port=port, observations=[],
                  utc=datetime.now(timezone.utc).isoformat(), monotonic_ns=time.monotonic_ns(),
                  probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    for option in ['-anl', '-an']:
        argv = [executable, option]
        row = dict(argv=argv, timeout_seconds=5, utc=datetime.now(timezone.utc).isoformat(),
                   monotonic_start_ns=time.monotonic_ns())
        try:
            child = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                                                     'LC_ALL': 'C'}, timeout=5)
            row.update(rc=child.returncode, stdout_bytes=len(child.stdout),
                       stdout_sha256=hashlib.sha256(child.stdout).hexdigest(),
                       stderr_bytes=len(child.stderr), stderr_sha256=hashlib.sha256(child.stderr).hexdigest())
            if len(child.stdout) > 256*1024 or len(child.stderr) > 8192:
                row.update(state='DROPPED', reason='OUTPUT_CAP', owned_lines=[])
            else:
                pattern = re.compile(rb'[:.]'+str(port).encode()+rb'(?:\s|$)')
                lines = [line for line in child.stdout.splitlines(keepends=True) if pattern.search(line)]
                raw = b''.join(lines)
                row.update(state='PRESENT' if raw else 'EMPTY', owned_lines=[s.decode('latin1') for s in lines],
                           owned_bytes=len(raw), owned_sha256=hashlib.sha256(raw).hexdigest(),
                           upstream_LISTEN_matches=sum(b'::' not in s and b'LISTEN' in s for s in lines),
                           stderr_hex=child.stderr.hex())
        except subprocess.TimeoutExpired:
            row.update(state='FAILED', reason='TIMEOUT', raw_state='NOT_ENABLED')
        except OSError:
            row.update(state='FAILED', reason='NATIVE_PROCESS_START_FAILED', raw_state='NOT_ENABLED')
        row['monotonic_end_ns'] = time.monotonic_ns()
        result['observations'].append(row)
    if connect:
        result['tcp_readiness'] = readiness(port)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--finder')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check-listening', action='store_true')
    parser.add_argument('--tcp', action='store_true')
    parser.add_argument('--owned-pid', type=int)
    args = parser.parse_args()
    if args.check_listening:
        return owned_listener(args.port, args.owned_pid)['rc'] if args.owned_pid is not None else readiness(args.port)['rc']
    if (args.finder is None and args.owned_pid is None) or args.output is None:
        parser.error('--finder and --output are required for observation')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Port observation destination already exists')
    report = owned_listener(args.port, args.owned_pid) if args.owned_pid is not None else observe(args.finder, args.port, connect=args.tcp)
    with args.output.open('x') as stream:
        stream.write(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    raise SystemExit(main())

"""Source-archive transport of the c12 recipes, installed over the shared pinned downloader.

The pinned SHA-256 of each archive, not its address, guarantees the content. So:
  * the requested address must still be an exact host of the component's route, but a redirect may lead to any
    HTTPS host with a DNS name (SourceForge picks a mirror at random); the archive is accepted only if its bytes match
    the pinned digest and size, which the caller checks, and every hop is written to the receipt (host and path; the
    signed query string is never kept);
  * a transient failure (curl transfer errors, HTTP 429/5xx) is retried at most three times after a pause of
    10, 30 and 60 seconds, each pause is written to the receipt;
  * HTTP/1.1 is forced: two runs lost the stream of one host (gstreamer.freedesktop.org) after exactly 1 MiB with
    curl rc=92 over HTTP/2;
  * a connection that stops after real progress (status 200, bytes received, transient curl error) is continued with
    a Range request instead of starting over; the finished file is still compared with the pinned digest and size.
The shared drivers (private_curl.py, public_archive.py, source_download.py) stay as pinned for the 1.0.9 recipe.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'repro109'))
import private_curl

PAUSES = (10, 30, 60)
MAX_RETRIES = len(PAUSES)
MAX_REDIRECTS = 5
MAX_SEGMENTS = 24
POLICY = dict(name='SOURCE_TRANSPORT_C12', redirects='ANY_HTTPS_DNS_HOST_IF_FINAL_BYTES_MATCH_PINNED_SHA256',
              redirect_record='STATUS_FROM_HOST_TO_HOST_TO_PATH_QUERY_OMITTED', retries=MAX_RETRIES,
              pauses_seconds=list(PAUSES), http_version='1.1_FORCED', resume='RANGE_AFTER_PROGRESS_THEN_PINNED_SHA256')
REDIRECT = (301, 302, 303, 307, 308)
_NAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')
_LOCAL_SUFFIXES = ('.local', '.localhost', '.internal', '.lan', '.home', '.corp')
_failures = {}
_lock = threading.Lock()


def _sleep(seconds):
    time.sleep(seconds)


def _curl(argv, config, seconds):
    env = {k: v for k, v in os.environ.items() if k not in {'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'}}
    return subprocess.run(argv, input=config.encode(), env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=seconds + 10)


def dns_host(host):
    return (isinstance(host, str) and len(host) <= 253 and _NAME.fullmatch(host) is not None and
            not re.fullmatch(r'[0-9.]+', host) and not host.endswith(_LOCAL_SUFFIXES))


def _argv(target, limit, seconds, resume):
    argv = ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--fail', '--http1.1',
            '--proto', '=https', '--connect-timeout', '30', '--max-time', str(seconds),
            '--max-filesize', str(limit), '--retry', '0', '--output', str(target),
            '--dump-header', '-', '--write-out', private_curl.MARKER + '%{http_code}\n%{url_effective}\n']
    if resume:
        argv += ['--continue-at', '-']
    return argv + ['--config', '-']


def _config(url):
    return ('url = ' + json.dumps(url) + '\n'
            'header = "Accept: application/octet-stream"\n'
            'header = "Accept-Encoding: identity"\n')


def _parse(child):
    if len(child.stdout) > private_curl.HEADER_LIMIT:
        raise ValueError('curl response headers exceed cap')
    headers, tail = child.stdout.decode('latin1').rsplit(private_curl.MARKER, 1)
    status, effective = tail.splitlines()[:2]
    final = headers.replace('\r\n', '\n').strip().split('\n\n')[-1]
    values = {}
    for line in final.splitlines()[1:]:
        key, sep, value = line.partition(':')
        if sep:
            values[key.lower()] = value.strip()
    return int(status), effective, values


def _destination(current, location):
    if not location:
        return None
    destination = urllib.parse.urljoin(current, location)
    parsed = urllib.parse.urlparse(destination)
    if (len(destination) > 2048 or parsed.scheme != 'https' or parsed.port not in (None, 443) or
            parsed.username or parsed.password or parsed.fragment or not dns_host(parsed.hostname)):
        return None
    return destination


def _scalars(result, values):
    for key in ('content-length', 'content-encoding', 'content-type', 'content-range'):
        if key in values:
            if len(values[key]) > 256:
                raise ValueError('response scalar refused')
            result[key.replace('-', '_')] = values[key]


def _fetch(url, target, limit, timeout_seconds):
    """One bounded transfer: follows redirects by hand, continues a cut connection, returns the receipt scalars."""
    target = Path(target)
    deadline = time.monotonic() + timeout_seconds
    chain, segments = [], []
    result = dict(curl_rc='NOT_RUN', http_status='NOT_ENABLED', content_length='EMPTY', content_encoding='identity',
                  content_type='EMPTY', content_range='EMPTY', final_host='NOT_ENABLED', redirects=0,
                  http_version='1.1_FORCED', redirect_chain=chain, segments=segments, resumed_segments=0,
                  stderr_state='NOT_SAVED_SENSITIVE_TRANSFER_DIAGNOSTICS')

    def fail(reason, retryable, stage=None):
        result.update(failure_reason=reason, retryable=retryable)
        if stage:
            result['failure_stage'] = stage
        return result

    current, resume, offset, total = url, False, 0, None
    while True:
        if time.monotonic() >= deadline:
            result.update(curl_rc='TIMEOUT')
            return fail('curl redirect deadline', True)
        seconds = max(1, int(deadline - time.monotonic()))
        try:
            child = _curl(_argv(target, limit, seconds, resume), _config(current), seconds)
        except subprocess.TimeoutExpired:
            result.update(curl_rc='TIMEOUT')
            return fail('curl process timeout', True)
        except OSError:
            raise ValueError('curl start failed; executable or local I/O unavailable') from None
        result.update(curl_rc=child.returncode, stderr_bytes=len(child.stderr))
        try:
            status, effective, values = _parse(child)
            if effective != current:
                raise ValueError('effective destination refused')
        except (ValueError, IndexError, TypeError):
            if not child.stdout and child.returncode in private_curl.TRANSIENT_CURL:
                return fail('curl transport failed before metadata; rc=' + str(child.returncode), True)
            return fail('curl response metadata or redirect destination refused', False)
        parsed = urllib.parse.urlparse(current)
        # Header scalars describe the response just received: a redirect's `Content-Length: 0` must not survive into the
        # final response, which may be chunked (codeload.github.com sends no length; 38528251057 lost two archives to it).
        result.update(http_status=status, final_host=parsed.hostname, final_path=parsed.path[:200],
                      content_length='EMPTY', content_encoding='identity', content_type='EMPTY', content_range='EMPTY')
        _scalars(result, values)
        segments.append(dict(status=status, rc=child.returncode, host=parsed.hostname, resumed=resume,
                             bytes_after=target.stat().st_size if target.is_file() else 0))
        if status in REDIRECT and child.returncode == 0 and not resume:
            destination = _destination(current, values.get('location', ''))
            if destination is None or len(chain) >= MAX_REDIRECTS:
                return fail('redirect destination refused', False, 'REDIRECT_DESTINATION_REFUSED')
            to = urllib.parse.urlparse(destination)
            chain.append(dict(status=status, from_host=parsed.hostname, to_host=to.hostname, to_path=to.path[:200],
                              query='OMITTED_SIGNED' if to.query else 'NONE'))
            result['redirects'] = len(chain)
            current = destination
            continue
        received = target.stat().st_size if target.is_file() else 0
        if resume and status == 206 and child.returncode == 0:
            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', values.get('content-range', ''))
            if not match or int(match.group(1)) != offset or int(match.group(2)) + 1 != int(match.group(3)):
                return fail('resumed range differs from the requested offset', True)
            if (total is not None and int(match.group(3)) != total) or received != int(match.group(3)):
                return fail('resumed body differs from the announced total', True)
            total = int(match.group(3))
            result.update(http_status=200, content_length=str(total), content_range='EMPTY',
                          resumed_segments=sum(1 for s in segments if s['resumed']))
            return result
        if status == 200 and child.returncode == 0 and not resume:
            return result
        if resume and (child.returncode == 33 or status in (200, 416)):
            # The server does not honour the byte range: the partial file is useless, the caller starts over.
            return fail('server did not honour the byte range', True)
        # A cut after real progress is continued from the byte reached; anything else is a plain failure.
        cut = (status in (200, 206) and child.returncode in private_curl.TRANSIENT_CURL and received > offset and
               len(segments) < MAX_SEGMENTS)
        if cut:
            if not resume:
                length = values.get('content-length', '')
                total = int(length) if length.isdigit() else None
            offset, resume = received, True
            continue
        reason, retryable = private_curl.transport_failure(child.returncode, status)
        result['resumed_segments'] = sum(1 for s in segments if s['resumed'])
        return fail(reason or 'curl transfer failed; rc=' + str(child.returncode), retryable)


def reset():
    with _lock:
        _failures.clear()


def source_transfer(url, target, limit, timeout_seconds=90, allowed_hosts=None):
    hosts = private_curl.SOURCE_HOSTS
    if allowed_hosts is not None:
        if (not isinstance(allowed_hosts, (list, tuple)) or not allowed_hosts or
                any(not isinstance(host, str) or not host or
                    any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in host) or
                    host.startswith('.') or host.endswith('.') or '..' in host
                    for host in allowed_hosts) or len(set(allowed_hosts)) != len(allowed_hosts)):
            raise ValueError('Source component exact host allowlist refused')
        hosts = set(allowed_hosts)
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme != 'https' or not private_curl._public_host_allowed(parsed.hostname, hosts) or
            parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment):
        raise ValueError('Public source origin refused')
    if type(limit) is not int or limit < 1 or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 90:
        raise ValueError('curl transfer limit or timeout refused')
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise ValueError('curl destination already exists')
    key = str(target.parent)
    with _lock:
        failures = _failures.get(key, 0)
    pause = PAUSES[min(failures, MAX_RETRIES) - 1] if failures else 0
    if pause:
        _sleep(pause)
    result = _fetch(url, target, limit, timeout_seconds)
    result.update(retry_number=failures, pause_before_seconds=pause, retry_policy=dict(
        retries=MAX_RETRIES, pauses_seconds=list(PAUSES)))
    if result.get('retryable'):
        with _lock:
            _failures[key] = failures + 1
        if failures >= MAX_RETRIES:
            result.update(retryable=False, retry_budget='EXHAUSTED')
    return result


def install(source_download):
    """Replace the shared module's transport name; its download() looks the name up at call time."""
    source_download.source_transfer = source_transfer
    return POLICY


def summarize(reports):
    """One readable table of what the transport did, from the per-archive receipts."""
    rows = {}
    for path in sorted((Path(reports) / 'public-archives').glob('*/receipt.json')):
        receipt = json.loads(path.read_text())
        attempts = receipt.get('attempts', [])
        rows[receipt['tool']] = dict(
            state=receipt.get('state'), attempts=len(attempts), failure_reason=receipt.get('failure_reason'),
            redirects=[dict(hop, attempt=a.get('number')) for a in attempts for hop in a.get('redirect_chain', [])],
            pauses_seconds=[a['pause_before_seconds'] for a in attempts if a.get('pause_before_seconds')],
            resumed_segments=sum(a.get('resumed_segments', 0) for a in attempts),
            final_hosts=sorted({a['final_host'] for a in attempts if a.get('final_host') not in (None, 'NOT_ENABLED')}))
    return dict(schema=1, policy=POLICY, components=rows,
                redirected=sorted(n for n, r in rows.items() if r['redirects']),
                retried=sorted(n for n, r in rows.items() if r['pauses_seconds']),
                resumed=sorted(n for n, r in rows.items() if r['resumed_segments']),
                failed=sorted(n for n, r in rows.items() if r['state'] != 'PRESENT'))

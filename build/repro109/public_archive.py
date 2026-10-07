"""Hash-pinned cloud tool downloads using the already exercised curl transport."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import time
import urllib.parse

from private_curl import public_transfer


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def download(row, destination, out, transfer=None):
    name = row['name']
    if not isinstance(name, str) or not re.fullmatch('[a-z0-9-]+', name):
        raise ValueError('Public tool name refused')
    size, digest = row.get('size'), row['sha256']
    limit = size if size is not None else row.get('maximum_size')
    if (type(limit) is not int or not 0 < limit <= 512 * 1024**2 or
            (size is not None and type(size) is not int) or
            not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest)):
        raise ValueError('Public tool sealed size/SHA refused')
    transfer = public_transfer if transfer is None else transfer
    urls = row.get('source_urls', [row['url']])
    if (not isinstance(urls, list) or not 1 <= len(urls) <= 3 or
            any(not isinstance(url, str) for url in urls) or urls[0] != row['url'] or
            len(set(urls)) != len(urls) or (len(urls) > 1 and 'source_route' not in row)):
        raise ValueError('Public archive source sequence refused')
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Public archive destination already exists')
    evidence = Path(out) / 'public-archives' / name
    evidence.mkdir(parents=True)
    receipt = dict(tool=name, state='STARTED', transport='CLOUD_CURL_PUBLIC',
                   expected_bytes=size if size is not None else 'NOT_ENABLED',
                   maximum_bytes=limit, expected_sha256=digest,
                   maximum_retries=5, time_cap_seconds=150, attempts=[])
    if 'source_route' in row:
        receipt['source_route'] = row['source_route']
        receipt['source_hosts'] = [urllib.parse.urlparse(url).hostname for url in urls]
    def record():
        (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    record()
    deadline = time.monotonic() + 150
    for number in range(1, 7):
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            receipt.update(state='FAILED', failure_reason='archive transfer deadline reached')
            break
        part = evidence / ('attempt-' + str(number) + '.body')
        source_index = min(number - 1, len(urls) - 1)
        requested_host = urllib.parse.urlparse(urls[source_index]).hostname
        attempt = dict(number=number, state='STARTED', source_index=source_index,
                       requested_host=requested_host, fallback_next_source=False)
        try:
            # Reserve time for every still-untried sealed endpoint under the
            # existing single 150-second budget; the last endpoint may retry.
            seconds = max(1, min(90, remaining // (len(urls) - source_index)))
            attempt['timeout_seconds'] = seconds
            response = transfer(urls[source_index], part, limit, timeout_seconds=seconds)
            attempt.update(response)
            received = part.stat().st_size if part.is_file() else 0
            observed = sha(part) if part.is_file() else hashlib.sha256(b'').hexdigest()
            attempt.update(received_bytes=received, received_sha256=observed,
                           missing_bytes=size-received if size is not None else 'NOT_ENABLED',
                           raw_body=dict(state='PRESENT' if received else ('EMPTY' if part.is_file() else 'NOT_ENABLED'),
                                         path=str(part.relative_to(out)), bytes=received, sha256=observed))
            reason, retryable = response.get('failure_reason'), response.get('retryable', False)
            length = response.get('content_length', 'EMPTY')
            if received > limit:
                reason, retryable = 'response exceeds pinned size', False
            elif response.get('curl_rc') != 0:
                # A failed TLS/connect/receive attempt commonly has HTTP 0. Keep
                # the real transport classifier's retry decision before checking
                # fields which only describe a complete successful HTTP 200 body.
                reason = reason or 'curl transport failed'
            elif reason is not None:
                # Do not turn an explicit transport metadata/redirect refusal
                # into a checksum mismatch eligible for another endpoint.
                pass
            elif response.get('http_status') != 200:
                reason = reason or 'expected HTTP 200'
            elif response.get('content_encoding', 'identity') not in ('', 'identity'):
                reason, retryable = 'server ignored identity encoding', False
            elif length not in ('EMPTY', 'NOT_ENABLED') and (not str(length).isdigit() or int(length) > limit):
                reason, retryable = 'invalid or over-cap Content-Length', False
            elif length not in ('EMPTY', 'NOT_ENABLED') and received != int(length):
                reason, retryable = 'received body differs from Content-Length', False
            elif (size is not None and received != size) or observed != digest:
                reason, retryable = 'archive checksum or size differs', False
            if reason is None:
                with part.open('rb') as source, destination.open('xb') as target:
                    shutil.copyfileobj(source, target)
                if destination.stat().st_size != received or sha(destination) != digest:
                    raise ValueError('Accepted public archive local copy differs')
                # Keep the verified raw bytes in the source input, rather than
                # publishing a second whole archive through reports/. Failed
                # attempts retain their byte-exact .body and report-relative path.
                part.unlink()
                attempt['raw_body'] = dict(state='PRESENT', storage='SOURCE_ARCHIVE',
                                         path=destination.name, path_base='SOURCE_ARCHIVE_PARENT',
                                         report_body_state='NOT_ENABLED',
                                         bytes=received, sha256=observed)
                attempt.update(state='PRESENT', body_complete=True, retryable=False)
                receipt['attempts'].append(attempt)
                receipt.update(state='PRESENT', bytes=received, sha256=observed,
                               selected_source_index=source_index, selected_source_host=requested_host,
                               selected_final_host=response.get('final_host', 'NOT_ENABLED'))
                record()
                return receipt
            # A wrong body is evidence about this endpoint, not about the next
            # independently sealed URL. Preserve it before trying that URL.
            # Certificate and local I/O failures retain their existing handling.
            fallback = source_index + 1 < len(urls) and (
                retryable or
                reason == 'archive checksum or size differs' or
                (reason == 'expected HTTP 200' and response.get('http_status') in (404, 410)) or
                (reason == response.get('failure_reason') and
                 response.get('failure_stage') == 'REDIRECT_DESTINATION_REFUSED'))
            attempt.update(state='FAILED', body_complete=False, failure_reason=reason,
                           retryable=retryable, fallback_next_source=fallback)
        except Exception as error:
            attempt.update(state='FAILED', retryable=False, error_type=type(error).__name__,
                           failure_reason=str(error) if type(error) is ValueError else 'curl or local I/O failure')
        receipt['attempts'].append(attempt)
        receipt.update(state='FAILED', failure_reason=attempt['failure_reason'])
        record()
        if (not attempt['retryable'] and not attempt['fallback_next_source']) or number == 6:
            break
        delay = min(3, max(0, deadline-time.monotonic()))
        if delay:
            time.sleep(delay)
    record()
    last = receipt['attempts'][-1] if receipt['attempts'] else {}
    raise ValueError('Public archive FAILED: tool=' + name + '; expected=' + str(size) + '/' + digest +
                     '; received=' + str(last.get('received_bytes', 'NOT_ENABLED')) + '/' +
                     str(last.get('received_sha256', 'NOT_ENABLED')) + '; HTTP=' +
                     str(last.get('http_status', 'NOT_ENABLED')) + '; Content-Length=' +
                     str(last.get('content_length', 'NOT_ENABLED')) + '; reason=' + receipt['failure_reason'])

"""Bounded cloud curl. API credentials use stdin; redirects receive no credentials."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse

ASSET_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'github.com'}
PUBLIC_HOSTS = ASSET_HOSTS | {'files.pythonhosted.org'}
SOURCE_HOSTS = PUBLIC_HOSTS | {'codeload.github.com', 'ftp.gnu.org',
    'downloads.xiph.org', 'downloads.sourceforge.net', '*.dl.sourceforge.net',
    'distfiles.ariadne.space', 'www.mpg123.de', 'download.gnome.org', 'www.gnupg.org',
    'gstreamer.freedesktop.org', 'ffmpeg.org', 'gitlab.freedesktop.org',
    'code.videolan.org', 'gitlab.com'}
MARKER = '\nREPRO109_CURL_META\n'
HEADER_LIMIT = 128 * 1024
TRANSIENT_CURL = {5, 6, 7, 18, 28, 35, 52, 55, 56, 92}


def transport_failure(curl_rc, status):
    """Classify the transport before validating a successful archive body."""
    if type(status) is int and 400 <= status < 500 and status != 429:
        return 'expected HTTP 200', False
    if curl_rc in TRANSIENT_CURL:
        return 'curl transfer failed; rc=' + str(curl_rc), True
    if status == 429 or (type(status) is int and 500 <= status < 600):
        return 'expected HTTP 200', True
    if status != 200:
        return 'expected HTTP 200', False
    if curl_rc:
        return 'curl transfer failed; rc=' + str(curl_rc), False
    return None, False


def private_api():
    remote = os.environ.get('RESULTS_REMOTE', '')
    if not remote:
        raise ValueError('RESULTS_REMOTE is required for private release access')
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/'
                        r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', remote):
        raise ValueError('RESULTS_REMOTE must be an explicit GitHub HTTPS repository URL without credentials')
    owner, repository = urllib.parse.urlparse(remote).path.strip('/').split('/')
    if repository.endswith('.git'):
        repository = repository[:-4]
    return 'https://api.github.com/repos/' + owner + '/' + repository


def transfer(asset_id, target, limit, timeout_seconds=90):
    if type(asset_id) is not int or asset_id < 1 or type(limit) is not int or limit < 1:
        raise ValueError('curl transfer identity/limit refused')
    api = private_api()
    token = os.environ.get('RESULTS_TOKEN') or os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if not token:
        raise ValueError('Private release access NOT_ENABLED: agreed cloud token is absent')
    if any(ord(c) < 32 or ord(c) > 126 for c in token):
        raise ValueError('Private release token format refused')
    url = api+'/releases/assets/'+str(asset_id)
    return _transfer(url, target, limit, timeout_seconds, token)


def public_transfer(url, target, limit, timeout_seconds=90):
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme != 'https' or parsed.hostname not in {'github.com', 'files.pythonhosted.org'} or
            parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment):
        raise ValueError('Public archive origin refused')
    return _transfer(url, target, limit, timeout_seconds, None)


def metadata_transfer(path, target, limit):
    if (path and not path.startswith('/')) or '..' in path.split('/') or '?' in path or '#' in path:
        raise ValueError('Private API path refused')
    api = private_api()
    token = os.environ.get('RESULTS_TOKEN') or os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if not token or any(ord(c) < 32 or ord(c) > 126 for c in token):
        raise ValueError('Private API credential unavailable or malformed')
    return _transfer(api + path, target, limit, 90, token,
                     accept='application/vnd.github+json', metadata_only=True)


def _public_host_allowed(host, hosts):
    return host in hosts or (isinstance(host, str) and
        '*.dl.sourceforge.net' in hosts and host.endswith('.dl.sourceforge.net') and
        len(host) > len('.dl.sourceforge.net'))


def source_transfer(url, target, limit, timeout_seconds=90, allowed_hosts=None):
    # The caller first validates the publisher/project against its sealed source lock.
    hosts = SOURCE_HOSTS
    if allowed_hosts is not None:
        if (not isinstance(allowed_hosts, (list, tuple)) or not allowed_hosts or
                any(not isinstance(host, str) or not host or
                    any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in host) or
                    host.startswith('.') or host.endswith('.') or '..' in host
                    for host in allowed_hosts) or len(set(allowed_hosts)) != len(allowed_hosts)):
            raise ValueError('Source component exact host allowlist refused')
        hosts = set(allowed_hosts)
    parsed = urllib.parse.urlparse(url)
    if (parsed.scheme != 'https' or not _public_host_allowed(parsed.hostname, hosts) or
            parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment):
        raise ValueError('Public source origin refused')
    return _transfer(url, target, limit, timeout_seconds, None, public_hosts=hosts)


def _transfer(url, target, limit, timeout_seconds, token, public_hosts=PUBLIC_HOSTS,
              accept='application/octet-stream', metadata_only=False):
    if type(limit) is not int or limit < 1:
        raise ValueError('curl transfer limit refused')
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 90:
        raise ValueError('curl transfer timeout refused')
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise ValueError('curl destination already exists')
    env = {k:v for k,v in os.environ.items() if k not in {'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'}}
    deadline = time.monotonic()+timeout_seconds
    for hop in range(6):
        seconds = max(1, int(deadline-time.monotonic()))
        if time.monotonic() >= deadline:
            return dict(curl_rc='TIMEOUT', http_status='NOT_ENABLED', content_length='NOT_ENABLED',
                        final_host='NOT_ENABLED', retryable=True, failure_reason='curl redirect deadline')
        config = ('url = '+json.dumps(url)+'\n'
                  'header = '+json.dumps('Accept: '+accept)+'\n'
                  'header = "Accept-Encoding: identity"\n')
        if hop == 0 and token is not None:
            config += ('header = '+json.dumps('Authorization: Bearer '+token)+'\n'
                       'header = "X-GitHub-Api-Version: 2022-11-28"\n')
        # No -L/--location: custom Authorization never participates in redirects.
        # --disable is first, so machine/user curlrc cannot add options/headers.
        # Five retries are in download(), preserving each failed raw body.
        argv = ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--fail',
                '--proto', '=https', '--connect-timeout', '30', '--max-time', str(seconds),
                '--max-filesize', str(limit), '--retry', '0', '--output', str(target),
                '--dump-header', '-', '--write-out', MARKER+'%{http_code}\n%{url_effective}\n',
                '--config', '-']
        try:
            child = subprocess.run(argv, input=config.encode(), env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=seconds+10)
        except subprocess.TimeoutExpired:
            return dict(curl_rc='TIMEOUT', http_status='NOT_ENABLED', content_length='NOT_ENABLED',
                        final_host='NOT_ENABLED', retryable=True, failure_reason='curl process timeout')
        except OSError:
            raise ValueError('curl start failed; executable or local I/O unavailable') from None
        result = dict(curl_rc=child.returncode, http_status='NOT_ENABLED', content_length='EMPTY',
                      content_encoding='identity', content_type='EMPTY', content_range='EMPTY',
                      final_host='NOT_ENABLED', redirects=hop, stderr_bytes=len(child.stderr),
                      stderr_state='NOT_SAVED_SENSITIVE_TRANSFER_DIAGNOSTICS')
        # Location/effective URL and stderr can contain signed queries or reflected
        # credentials. Preserve only bounded final-response scalars, never these bytes.
        if len(child.stdout) > HEADER_LIMIT:
            result.update(failure_reason='curl response headers exceed cap', retryable=False)
            return result
        try:
            headers, tail = child.stdout.decode('latin1').rsplit(MARKER, 1)
            status, effective = tail.splitlines()[:2]
            parsed = urllib.parse.urlparse(effective)
            allowed = ({'api.github.com'} if hop == 0 else ASSET_HOSTS) if token is not None else public_hosts
            if (parsed.scheme != 'https' or not _public_host_allowed(parsed.hostname, allowed) or
                    parsed.port not in (None,443) or parsed.username or parsed.password or
                    effective != url):
                raise ValueError('effective destination refused')
            result.update(http_status=int(status),final_host=parsed.hostname)
            final = headers.replace('\r\n','\n').strip().split('\n\n')[-1]
            values = {}
            for line in final.splitlines()[1:]:
                key,sep,value=line.partition(':')
                if sep:values[key.lower()]=value.strip()
            for key in ['content-length','content-encoding','content-type','content-range']:
                if key in values:
                    value=values[key]
                    if len(value)>256 or (token is not None and token in value):
                        raise ValueError('response scalar refused')
                    result[key.replace('-','_')]=value
            if result['http_status'] in (301,302,303,307,308) and child.returncode == 0:
                if metadata_only:
                    raise ValueError('Private API metadata redirect refused')
                location=values.get('location','')
                destination=urllib.parse.urlparse(location)
                redirect_hosts = ASSET_HOSTS if token is not None else public_hosts
                if (hop == 5 or destination.scheme != 'https' or not _public_host_allowed(destination.hostname, redirect_hosts) or
                        destination.port not in (None,443) or destination.username or destination.password or destination.fragment or
                        (token is not None and token in location)):
                    result['failure_stage'] = 'REDIRECT_DESTINATION_REFUSED'
                    raise ValueError('redirect destination refused')
                url=location
                continue
            reason, retryable = transport_failure(child.returncode, result['http_status'])
            if reason:
                result.update(failure_reason=reason, retryable=retryable)
        except (ValueError,IndexError,TypeError):
            if not child.stdout and child.returncode in TRANSIENT_CURL:
                result.update(failure_reason='curl transport failed before metadata; rc='+str(child.returncode),
                              retryable=True)
            else:
                result.update(failure_reason='curl response metadata or redirect destination refused',retryable=False)
        return result
    raise ValueError('curl redirect count exceeded')

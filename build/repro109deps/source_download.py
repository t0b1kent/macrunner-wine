"""Use the existing cloud curl transport for sealed official source archives."""
import hashlib
from functools import partial
import json
from pathlib import Path
import sys
import tarfile
import urllib.parse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'repro109'))
import public_archive
from private_curl import source_transfer
import archive_safety


def read_pins():
    pins = json.loads((HERE / 'download-sizes.lock.json').read_text())
    if hashlib.sha256((HERE / 'deps.lock.json').read_bytes()).hexdigest() != pins['deps_lock_sha256']:
        raise ValueError('Source download size pins belong to a different dependency lock')
    rows = json.loads((HERE / 'deps.lock.json').read_text())['components']
    archives = {r['name'] for r in rows if r.get('source_kind') != 'git'}
    sizes = pins['component_sizes_lines']
    missing = pins['unpinned_sizes']
    if (set(sizes) | set(missing) != archives or set(sizes) & set(missing) or
            missing != ['ffmpeg', 'gst-libav'] or len(sizes) != 44):
        raise ValueError('Source download size coverage differs')
    if any(type(v) is not list or len(v) != 2 or type(v[0]) is not int or
           not 0 < v[0] <= 256 * 1024**2 or type(v[1]) is not int or v[1] < 1
           for v in sizes.values()):
        raise ValueError('Source archive size/receipt line refused')
    return pins


def download(row, destination, out):
    pins = read_pins()
    locked = {r['name']: r for r in json.loads((HERE / 'deps.lock.json').read_text())['components']}
    expected = locked[row['name']]
    if any(row[key] != expected[key] for key in ['url', 'sha256']):
        raise ValueError('Source download URL/SHA differs from locked publisher')
    request = dict(name=row['name'], url=row['url'], sha256=row['sha256'])
    if row['name'] in pins['component_sizes_lines']:
        request['size'] = pins['component_sizes_lines'][row['name']][0]
    elif row['name'] in pins['unpinned_sizes']:
        request['maximum_size'] = 256 * 1024**2
    else:
        raise ValueError('Source archive size coverage missing')
    routes = read_routes()
    route = routes['routes'][row['name']]
    if row['url'] != route['url']:
        raise ValueError('Source route URL differs from locked publisher')
    transfer = partial(source_transfer, allowed_hosts=route['allowed_hosts'])
    request['source_urls'] = [row['url']] + route.get('mirror_urls', [])
    request['source_route'] = dict(component=row['name'], allowed_hosts=route['allowed_hosts'],
                                  route_lock_sha256=hashlib.sha256((HERE/'source-routes.lock.json').read_bytes()).hexdigest())
    return public_archive.download(request, destination, out, transfer=transfer)


def read_routes():
    routes = json.loads((HERE/'source-routes.lock.json').read_text())
    raw = (HERE/'deps.lock.json').read_bytes()
    if (routes.get('schema') != 1 or routes.get('scope') != 'EXACT_COMPONENT_HOSTS_HTTPS_ONLY_NO_WILDCARDS' or
            routes.get('deps_lock_sha256') != hashlib.sha256(raw).hexdigest()):
        raise ValueError('Source route lock identity refused')
    rows = [r for r in json.loads(raw)['components'] if r.get('source_kind') != 'git']
    if not isinstance(routes.get('routes'), dict) or set(routes['routes']) != {r['name'] for r in rows}:
        raise ValueError('Source route component coverage differs')
    for row in rows:
        route = routes['routes'][row['name']]
        if not isinstance(route, dict) or route.get('url') != row['url']:
            raise ValueError('Source route URL differs from locked publisher')
        hosts = route.get('allowed_hosts')
        if (not isinstance(hosts, list) or not hosts or
                any(not isinstance(h, str) or not h or
                    any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in h) or
                    h.startswith('.') or h.endswith('.') or '..' in h for h in hosts) or
                len(set(hosts)) != len(hosts) or
                urllib.parse.urlparse(row['url']).hostname not in hosts):
            raise ValueError('Source route exact hosts refused')
        origin = urllib.parse.urlparse(row['url']).hostname
        official_hosts = {origin}
        if origin == 'ftp.gnu.org':
            parsed = urllib.parse.urlparse(row['url'])
            if (parsed.scheme != 'https' or parsed.netloc != 'ftp.gnu.org' or
                    not parsed.path.startswith('/gnu/') or parsed.query or parsed.fragment):
                raise ValueError('GNU source primary URL refused')
            mirrors = ['https://ftpmirror.gnu.org/' + parsed.path[len('/gnu/'):],
                       'https://mirrors.kernel.org' + parsed.path]
            if route.get('mirror_urls') != mirrors:
                raise ValueError('GNU source mirror order/path differs from locked publisher')
            official_hosts.update({'ftpmirror.gnu.org', 'mirrors.kernel.org'})
            if set(hosts) != official_hosts:
                raise ValueError('GNU source mirror exact hosts differ')
        elif origin == 'downloads.sourceforge.net':
            parsed = urllib.parse.urlparse(row['url'])
            if (parsed.scheme != 'https' or parsed.netloc != origin or
                    not parsed.path.startswith('/project/' + row['name'] + '/') or
                    parsed.query or parsed.fragment):
                raise ValueError('SourceForge source primary URL refused')
            mirrors = ['https://' + host + parsed.path for host in
                       ('cfhcable.dl.sourceforge.net', 'gigenet.dl.sourceforge.net')]
            if route.get('mirror_urls') != mirrors:
                raise ValueError('SourceForge source mirror order/path differs from locked publisher')
            if not all(urllib.parse.urlparse(url).hostname in hosts for url in mirrors):
                raise ValueError('SourceForge source mirror exact hosts missing')
        elif 'mirror_urls' in route:
            raise ValueError('Source mirror list is only enabled for GNU/SourceForge components')
        if origin == 'github.com':
            official_hosts.add('codeload.github.com' if '/archive/' in row['url'] else 'release-assets.githubusercontent.com')
        elif origin == 'downloads.xiph.org':
            official_hosts.add('ftp.osuosl.org')
        elif origin == 'downloads.sourceforge.net':
            official_hosts.update({'cfhcable.dl.sourceforge.net', 'gigenet.dl.sourceforge.net', 'netactuate.dl.sourceforge.net'})
            # Exact b27/b30 publisher redirects; no wildcard or cross-component grant.
            official_hosts.update({'libpng': {'psychz.dl.sourceforge.net'},
                                   'freetype': {'psychz.dl.sourceforge.net'},
                                   'lame': {'phoenixnap.dl.sourceforge.net'}}.get(row['name'], set()))
        if not set(hosts).issubset(official_hosts):
            raise ValueError('Source route host is not an official mirror of this component')
    return routes


def extract_tar(stream, members, destination, evidence=None):
    graph = archive_safety.validate_tar(members)
    if evidence is not None:
        Path(evidence).parent.mkdir(parents=True, exist_ok=True)
        Path(evidence).write_text(json.dumps(graph, indent=2)+'\n')
    if callable(getattr(tarfile, 'data_filter', None)):
        stream.extractall(destination, members=members, filter='data')
    else:
        stream.extractall(destination, members=members)
    return graph

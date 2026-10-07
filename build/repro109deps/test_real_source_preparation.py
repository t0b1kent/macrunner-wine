"""Real archive preparation; only curl execution and synthetic pin location replaced.

Official URLs/names are read from the production lock. All 46 archive bytes and
their SHA/size pins are explicitly SYNTHETIC_OWNED_FIXTURES, not publisher data.
No compiler, source code, generated tool or external payload is executed.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import urllib.parse
from unittest.mock import patch

import build_deps as deps
import source_download as source
import private_curl


class RealSourcePreparation(unittest.TestCase):
    def test_all_46_real_download_to_unpack_routes_only_curl_is_disk_fed(self):
        production = deps.read_lock()
        pins = source.read_pins()
        routes = source.read_routes()
        fixture_lock = copy.deepcopy(production)
        rows = [row for row in fixture_lock['components'] if row.get('source_kind') != 'git']
        self.assertEqual(len(rows), 46)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            locked, payloads, reports = root/'synthetic-lock', root/'disk-payloads', root/'reports'
            for path in [locked, payloads, reports]:
                path.mkdir()
            by_url, redirects = {}, {}
            for row in rows:
                leaf = row['url'].rsplit('/', 1)[-1]
                mode = 'w:gz' if leaf.endswith('.gz') else 'w:bz2' if leaf.endswith('.bz2') else 'w:xz'
                archive = payloads/(row['name']+'.tar')
                with tarfile.open(archive, mode) as stream:
                    for name, kind, target in [
                        ('owned', tarfile.DIRTYPE, ''),
                        ('owned/fixture.txt', tarfile.REGTYPE, ''),
                        ('owned/alias', tarfile.SYMTYPE, 'fixture.txt'),
                        ('owned/chain', tarfile.SYMTYPE, 'alias')]:
                        member = tarfile.TarInfo(name)
                        member.type, member.linkname = kind, target
                        member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
                        body = ('OWNED FIXTURE '+row['name']+'\n').encode()
                        if kind == tarfile.REGTYPE:
                            member.size = len(body)
                            stream.addfile(member, io.BytesIO(body))
                        else:
                            stream.addfile(member)
                row['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
                if row['name'] in pins['component_sizes_lines']:
                    pins['component_sizes_lines'][row['name']][0] = archive.stat().st_size
                by_url[row['url']] = archive
                origin = urllib.parse.urlparse(row['url'])
                mirrors = [h for h in routes['routes'][row['name']]['allowed_hosts'] if h != origin.hostname]
                if mirrors:
                    final = origin._replace(netloc=mirrors[0]).geturl()
                    if origin.hostname == 'downloads.xiph.org':
                        final = origin._replace(netloc=mirrors[0], path='/pub/xiph'+origin.path).geturl()
                    redirects[row['url']] = final
                    by_url[final] = archive
            raw_lock = json.dumps(fixture_lock, sort_keys=True).encode()
            (locked/'deps.lock.json').write_bytes(raw_lock)
            pins['deps_lock_sha256'] = hashlib.sha256(raw_lock).hexdigest()
            (locked/'download-sizes.lock.json').write_text(json.dumps(pins))
            routes['deps_lock_sha256'] = hashlib.sha256(raw_lock).hexdigest()
            (locked/'source-routes.lock.json').write_text(json.dumps(routes))
            calls = []

            def disk_curl(argv, **kwargs):
                self.assertEqual(argv[0], '/usr/bin/curl')
                self.assertNotIn('--location', argv)
                self.assertFalse({'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'} & set(kwargs['env']))
                config = kwargs['input'].decode()
                self.assertNotIn('Authorization:', config)
                self.assertNotIn('owned-fixture-secret', config)
                url = json.loads(next(line[6:] for line in config.splitlines() if line.startswith('url = ')))
                payload = by_url[url]
                target = Path(argv[argv.index('--output')+1])
                if url in redirects:
                    target.write_bytes(b'owned-302')
                else:
                    shutil.copyfile(payload, target)
                body_size = target.stat().st_size
                calls.append(dict(component=payload.stem, bytes=body_size,
                                  sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
                if url in redirects:
                    header = ('HTTP/1.1 302 Found\r\nLocation: '+redirects[url]+'\r\nContent-Length: '+str(body_size)+
                              '\r\n\r\n'+private_curl.MARKER+'302\n'+url+'\n')
                else:
                    header = ('HTTP/1.1 200 OK\r\nContent-Length: '+str(body_size)+
                              '\r\nContent-Encoding: identity\r\n\r\n'+private_curl.MARKER+'200\n'+url+'\n')
                return subprocess.CompletedProcess(argv, 0, header.encode(), b'')

            observed = []
            with patch.object(source, 'HERE', locked), \
                 patch.dict(os.environ, {'RESULTS_TOKEN': 'owned-fixture-secret'}), \
                 patch.object(private_curl.subprocess, 'run', autospec=True, side_effect=disk_curl) as process:
                for row in rows:
                    destination = root/(row['name']+'.archive')
                    # These are the same calls as the actual source-batch loop.
                    deps.download(row, destination, reports)
                    selected = deps.unpack(destination, root/(row['name']+'-source'))
                    expected = ('OWNED FIXTURE '+row['name']+'\n').encode()
                    self.assertEqual((selected/'chain').read_bytes(), expected)
                    receipt = json.loads((reports/'public-archives'/row['name']/'receipt.json').read_text())
                    self.assertEqual(receipt['state'], 'PRESENT')
                    self.assertEqual(receipt['sha256'], row['sha256'])
                    self.assertEqual(receipt['expected_bytes'] == 'NOT_ENABLED', row['name'] in ['ffmpeg', 'gst-libav'])
                    self.assertEqual(len(receipt['attempts']), 1)
                    self.assertEqual(receipt['attempts'][0]['redirects'], int(row['url'] in redirects))
                    self.assertEqual(receipt['source_route']['allowed_hosts'], routes['routes'][row['name']]['allowed_hosts'])
                    observed.append(dict(component=row['name'], download=receipt['state'],
                                         sha256=receipt['sha256'], extraction='PRESENT',
                                         exact_size=receipt['expected_bytes']))
                self.assertEqual(process.call_count, 46+len(redirects))
            timeline = [json.loads(line) for line in (reports/'timeline.jsonl').read_text().splitlines()]
            self.assertEqual(len(timeline), 46)
            self.assertEqual({row['state'] for row in timeline}, {'ARCHIVE_PRESENT'})
            result = dict(classification='SYNTHETIC_OWNED_FIXTURES_NOT_EXTERNAL_SOURCE_ACCEPTANCE',
                          production_lock_sha256=hashlib.sha256((deps.HERE/'deps.lock.json').read_bytes()).hexdigest(),
                          real_functions=['build_deps.download', 'source_download.read_pins',
                              'source_download.download', 'public_archive.download',
                              'private_curl.source_transfer', 'private_curl._transfer',
                              'build_deps.unpack', 'build_deps.source_root',
                              'source_download.extract_tar', 'archive_safety.validate_tar'],
                          replaced=['source_download.HERE', 'private_curl.subprocess.run'],
                          production_archive_pins='NOT_ENABLED', git_source_x264='NOT_ENABLED',
                          curl_calls=calls, components=observed, install_skipped=True,
                          external_downloads=0, source_builds=0, external_execution=0)
            (root/'real-source-preparation.json').write_text(json.dumps(result, indent=2)+'\n')
            save = os.environ.get('REPRO109_REAL_SOURCE_EVIDENCE')
            if save:
                destination = Path(save)
                self.assertFalse(destination.exists())
                shutil.copytree(root, destination, symlinks=True)


if __name__ == '__main__':
    unittest.main()

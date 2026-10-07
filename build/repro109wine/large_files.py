#!/usr/bin/env python3
"""Read the public Wine publisher's schema 1 and verify an explicitly supplied archive.

No network calls, downloads, extraction, execution, or environment credentials.
UPLOADED is publisher metadata; archive bytes require a separate verification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

REPOSITORY = 't0b1kent/macrunner-wine'
MANIFEST_LIMIT = 4 * 1024**2
STATES = {'PENDING', 'UPLOADED', 'INCOMPLETE'}
ASSET_STATES = {'PENDING', 'UPLOADED', 'FAILED'}


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def relative_path(value):
    return (isinstance(value, str) and 0 < len(value) <= 1024 and
            not any(ord(c) < 32 or c == '\\' for c in value) and
            all(part not in ('', '.', '..') for part in value.split('/')))


def digest(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def parse_manifest(raw, destination):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MANIFEST_LIMIT,
            'Manifest bytes missing or exceed cap')
    require(relative_path(destination) and destination.startswith('runs/') and
            len(destination.split('/')) == 2, 'Expected exact run destination')
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(value, dict) and type(value.get('schema')) is int and
            value['schema'] == 1, 'Unsupported manifest schema')
    require(value.get('destination') == destination, 'Manifest run destination differs')
    require(isinstance(value.get('state'), str) and value['state'] in STATES,
            'Unknown manifest state')
    require(integer(value.get('limit_bytes'), 1), 'Invalid publisher size limit')
    release = value.get('release')
    require(isinstance(release, dict), 'Missing release object')
    tag = 'results-' + destination.split('/')[-1]
    require(release.get('tag') == tag and release.get('prerelease') is True,
            'Release tag or prerelease differs')
    rid = release.get('id')
    require(rid is None or integer(rid, 1), 'Invalid release identifier')
    url = release.get('html_url')
    if url is not None:
        require(isinstance(url, str), 'Invalid release URL type')
        parsed = urlsplit(url)
        require(parsed.scheme == 'https' and parsed.netloc == 'github.com' and
                parsed.path == '/' + REPOSITORY + '/releases/tag/' + tag and
                not parsed.query and not parsed.fragment, 'Release URL differs')
    require(value['state'] != 'UPLOADED' or (rid is not None and url is not None),
            'Uploaded manifest lacks release identity')
    files = value.get('files')
    require(isinstance(files, list) and 0 < len(files) <= 1024, 'Invalid large file count')
    paths, names, ids = set(), set(), set()
    asset_count = 0
    for item in files:
        require(isinstance(item, dict), 'Large file must be an object')
        name = item.get('path')
        require(relative_path(name) and name not in paths, 'Unsafe or duplicate file path')
        paths.add(name)
        require(integer(item.get('bytes'), value['limit_bytes'] + 1) and
                digest(item.get('sha256')), 'Invalid file size or SHA-256')
        assets = item.get('assets')
        require(isinstance(assets, list) and 0 < len(assets) <= 1024, 'Invalid asset count')
        asset_count += len(assets)
        require(asset_count <= 4096, 'Combined asset count exceeds cap')
        offset = 0
        for asset in assets:
            require(isinstance(asset, dict), 'Asset must be an object')
            aname = asset.get('name')
            require(isinstance(aname, str) and len(aname) <= 255 and
                    re.fullmatch(r'[A-Za-z0-9_.-]+', aname) is not None and
                    aname not in ('.', '..') and aname not in names,
                    'Unsafe or duplicate asset name')
            names.add(aname)
            require(integer(asset.get('offset')) and asset['offset'] == offset and
                    integer(asset.get('bytes'), 1) and digest(asset.get('sha256')),
                    'Asset range, size or SHA-256 differs')
            offset += asset['bytes']
            require(offset <= item['bytes'], 'Asset extends past file')
            require(isinstance(asset.get('state'), str) and asset['state'] in ASSET_STATES and
                    integer(asset.get('attempts')), 'Invalid asset state or attempts')
            aid = asset.get('id')
            require(aid is None or (integer(aid, 1) and aid not in ids),
                    'Invalid or duplicate asset identifier')
            if aid is not None:
                ids.add(aid)
            error = asset.get('error')
            require(error is None or isinstance(error, str), 'Invalid asset error type')
            if asset['state'] == 'UPLOADED':
                require(aid is not None and rid is not None and asset['attempts'] >= 1 and
                        error is None, 'Uploaded asset lacks successful identity')
            require(value['state'] != 'UPLOADED' or asset['state'] == 'UPLOADED',
                    'Final manifest includes an unavailable asset')
        require(offset == item['bytes'], 'Asset ranges do not cover the file')
        if len(assets) == 1:
            require(assets[0]['sha256'] == item['sha256'], 'Single asset/file SHA-256 differs')
    return value


def summarize(manifest):
    """Never echo error bodies or URLs; preserve them only in the caller's raw capture."""
    return dict(manifest_coverage='PRESENT', publication_state=manifest['state'],
                destination=manifest['destination'], release_tag=manifest['release']['tag'],
                bytes_coverage='NOT_ENABLED', files=[dict(
                    path=item['path'], bytes=item['bytes'], sha256=item['sha256'],
                    assets=len(item['assets']), asset_states=[a['state'] for a in item['assets']],
                    upload_errors=sum(a['error'] is not None for a in item['assets']),
                    archive_verification='NOT_ENABLED') for item in manifest['files']])


def verify_archive(manifest, name, assembled):
    """Verify all part hashes and the whole file, streaming without extraction."""
    matching = [item for item in manifest['files'] if item['path'] == name]
    require(len(matching) == 1, 'Selected archive is not in the manifest')
    item = matching[0]
    require(manifest['state'] == 'UPLOADED' and
            all(a['state'] == 'UPLOADED' for a in item['assets']),
            'Archive upload is not complete')
    descriptor = os.open(assembled, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size == item['bytes'],
                'Archive is not a regular file of the expected size')
        whole = hashlib.sha256()
        for asset in item['assets']:
            part, remaining = hashlib.sha256(), asset['bytes']
            while remaining:
                chunk = stream.read(min(1024**2, remaining))
                require(chunk, 'Archive became shorter during verification')
                whole.update(chunk)
                part.update(chunk)
                remaining -= len(chunk)
            require(part.hexdigest() == asset['sha256'], 'Archive part SHA-256 differs')
        require(not stream.read(1), 'Archive became longer during verification')
        require(whole.hexdigest() == item['sha256'], 'Archive whole SHA-256 differs')
    return dict(path=name, bytes=item['bytes'], sha256=item['sha256'],
                parts=len(item['assets']), bytes_coverage='PRESENT',
                archive_verification='MATCH', extraction='NOT_ENABLED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--file')
    parser.add_argument('--assembled', type=Path)
    args = parser.parse_args()
    if bool(args.file) != bool(args.assembled):
        parser.error('--file and --assembled must be supplied together')
    require(args.manifest.stat().st_size <= MANIFEST_LIMIT, 'Manifest exceeds cap')
    manifest = parse_manifest(args.manifest.read_bytes(), args.destination)
    result = summarize(manifest)
    if args.file:
        result['verified_archive'] = verify_archive(manifest, args.file, args.assembled)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

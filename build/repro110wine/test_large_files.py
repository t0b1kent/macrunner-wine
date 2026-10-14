#!/usr/bin/env python3
"""Owned tiny publisher fixtures; no downloads, tools, or game inputs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import large_files as reader

DEST = 'runs/20261006T114021Z-b42-publish-selftest'
BODY = b'owned-fixture-part-A|owned-fixture-part-B'


def fixture(split=True):
    parts = [BODY[:19], BODY[19:]] if split else [BODY]
    assets, offset = [], 0
    for index, part in enumerate(parts):
        assets.append(dict(name='wine-dist.tar.gz.part' + str(index), offset=offset,
                           bytes=len(part), sha256=hashlib.sha256(part).hexdigest(),
                           state='UPLOADED', id=100 + index, attempts=1, error=None))
        offset += len(part)
    tag = 'results-' + DEST.split('/')[-1]
    return dict(schema=1, state='UPLOADED', limit_bytes=1, destination=DEST,
                release=dict(tag=tag, id=7, prerelease=True,
                             html_url='https://github.com/' + reader.REPOSITORY +
                             '/releases/tag/' + tag),
                files=[dict(path='wine-dist.tar.gz', bytes=len(BODY),
                            sha256=hashlib.sha256(BODY).hexdigest(), assets=assets)])


def parsed(value=None):
    return reader.parse_manifest(json.dumps(value or fixture()).encode(), DEST)


class LargeFiles(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='owned-large-files-', dir=os.environ.get('TMPDIR')))
        self.archive = self.root / 'archive.bin'
        self.archive.write_bytes(BODY)
        # Keep these small authored fixtures; no automatic cleanup of evidence.

    def reject(self, value):
        with self.assertRaises((ValueError, TypeError)):
            parsed(value)

    def test_uploaded_metadata_does_not_verify_bytes(self):
        result = reader.summarize(parsed())
        self.assertEqual(result['publication_state'], 'UPLOADED')
        self.assertEqual(result['bytes_coverage'], 'NOT_ENABLED')
        self.assertEqual(result['files'][0]['archive_verification'], 'NOT_ENABLED')

    def test_split_archive_bytes_and_whole_hash(self):
        result = reader.verify_archive(parsed(), 'wine-dist.tar.gz', self.archive)
        self.assertEqual(result['parts'], 2)
        self.assertEqual(result['archive_verification'], 'MATCH')

    def test_unsplit_archive(self):
        self.assertEqual(reader.verify_archive(parsed(fixture(False)), 'wine-dist.tar.gz',
                                              self.archive)['parts'], 1)

    def test_pending_receipt_is_present(self):
        value = fixture()
        value['state'] = 'PENDING'
        value['release']['id'] = value['release']['html_url'] = None
        for a in value['files'][0]['assets']:
            a.update(state='PENDING', id=None, attempts=0)
        result = reader.summarize(parsed(value))
        self.assertEqual(result['manifest_coverage'], 'PRESENT')
        self.assertEqual(result['publication_state'], 'PENDING')

    def test_incomplete_release_and_private_error(self):
        value = fixture()
        value['state'] = 'INCOMPLETE'
        value['release']['id'] = value['release']['html_url'] = None
        for a in value['files'][0]['assets']:
            a.update(state='FAILED', id=None, error='private fixture body must not be echoed')
        result = reader.summarize(parsed(value))
        self.assertEqual(result['files'][0]['upload_errors'], 2)
        self.assertNotIn('private fixture', json.dumps(result))

    def test_pending_with_one_uploaded_part(self):
        value = fixture()
        value['state'] = 'PENDING'
        value['files'][0]['assets'][1].update(state='PENDING', id=None, attempts=0)
        self.assertEqual(parsed(value)['state'], 'PENDING')

    def test_destination_drift(self):
        value = fixture(); value['destination'] = 'runs/other'
        self.reject(value)

    def test_release_tag_drift(self):
        value = fixture(); value['release']['tag'] = 'results-other'
        self.reject(value)

    def test_signed_or_foreign_urls(self):
        for url in ['https://example.invalid/asset',
                    fixture()['release']['html_url'] + '?private=fixture',
                    fixture()['release']['html_url'] + '#fragment']:
            with self.subTest(url_shape=url.split('?')[0]):
                value = fixture(); value['release']['html_url'] = url
                self.reject(value)

    def test_unsafe_paths(self):
        for name in ['../escape', '/absolute', 'a//b', 'a/./b', 'a/../b', 'a\\b', 'nul\0']:
            with self.subTest(shape=repr(name)):
                value = fixture(); value['files'][0]['path'] = name
                self.reject(value)

    def test_duplicate_file_paths(self):
        value = fixture(); value['files'].append(copy.deepcopy(value['files'][0]))
        self.reject(value)

    def test_duplicate_asset_names(self):
        value = fixture(); value['files'][0]['assets'][1]['name'] = value['files'][0]['assets'][0]['name']
        self.reject(value)

    def test_duplicate_asset_ids(self):
        value = fixture(); value['files'][0]['assets'][1]['id'] = value['files'][0]['assets'][0]['id']
        self.reject(value)

    def test_gap_overlap_and_reversed_parts(self):
        for offset in [0, 18, 20]:
            with self.subTest(offset=offset):
                value = fixture(); value['files'][0]['assets'][1]['offset'] = offset
                self.reject(value)
        value = fixture(); value['files'][0]['assets'].reverse()
        self.reject(value)

    def test_file_coverage(self):
        value = fixture(); value['files'][0]['bytes'] += 1
        self.reject(value)

    def test_small_file_should_remain_in_results(self):
        value = fixture(); value['limit_bytes'] = len(BODY)
        self.reject(value)

    def test_boolean_numeric_fields(self):
        for key in ['schema', 'limit_bytes']:
            value = fixture(); value[key] = True
            self.reject(value)
        for key in ['offset', 'bytes', 'id', 'attempts']:
            value = fixture(); value['files'][0]['assets'][0][key] = True
            self.reject(value)

    def test_wrong_collection_and_state_types(self):
        for key in ['state', 'files', 'release']:
            value = fixture(); value[key] = [] if key != 'files' else {}
            self.reject(value)
        value = fixture(); value['files'][0]['assets'] = {}
        self.reject(value)
        value = fixture(); value['files'][0]['assets'][0]['state'] = []
        self.reject(value)

    def test_duplicate_json_keys(self):
        raw = json.dumps(fixture()).encode().replace(b'"schema": 1', b'"schema": 1, "schema": 1')
        with self.assertRaises(ValueError):
            reader.parse_manifest(raw, DEST)

    def test_final_state_contradiction(self):
        value = fixture(); value['files'][0]['assets'][0]['state'] = 'FAILED'
        self.reject(value)

    def test_upload_missing_identity(self):
        value = fixture(); value['files'][0]['assets'][0]['id'] = None
        self.reject(value)

    def test_single_asset_file_hash_consistency(self):
        value = fixture(False); value['files'][0]['sha256'] = '0' * 64
        self.reject(value)

    def test_part_hash_corruption(self):
        value = fixture(); value['files'][0]['assets'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            reader.verify_archive(parsed(value), 'wine-dist.tar.gz', self.archive)

    def test_whole_hash_corruption(self):
        value = fixture(); value['files'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            reader.verify_archive(parsed(value), 'wine-dist.tar.gz', self.archive)

    def test_short_and_long_local_archives(self):
        for body in [BODY[:-1], BODY + b'extra']:
            self.archive.write_bytes(body)
            with self.assertRaises(ValueError):
                reader.verify_archive(parsed(), 'wine-dist.tar.gz', self.archive)

    def test_pending_archive_cannot_be_accepted(self):
        value = fixture(); value['state'] = 'PENDING'
        with self.assertRaises(ValueError):
            reader.verify_archive(parsed(value), 'wine-dist.tar.gz', self.archive)

    def test_unlisted_archive(self):
        with self.assertRaises(ValueError):
            reader.verify_archive(parsed(), 'other.tar.gz', self.archive)

    def test_symlink_archive(self):
        link = self.root / 'link.bin'
        link.symlink_to(self.archive)
        with self.assertRaises(OSError):
            reader.verify_archive(parsed(), 'wine-dist.tar.gz', link)


if __name__ == '__main__':
    unittest.main()

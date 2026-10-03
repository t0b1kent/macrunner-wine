#!/usr/bin/env python3
"""Report MATCH/DIFFERENT/MISSING without treating compiler drift as failure."""
import csv
import hashlib
import json
from pathlib import Path
import sys

def main():
    install = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parent.parent
    with (root / 'docs/release-1.0.7-sha256.tsv').open() as stream:
        expected = list(csv.DictReader(stream, delimiter='\t'))
    rows = []
    for item in expected:
        path = install / item['path']
        actual = None
        if path.is_file():
            with path.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        status = 'MISSING' if actual is None else ('MATCH' if actual == item['sha256'] else 'DIFFERENT')
        rows.append({'path': item['path'], 'release_sha256': item['sha256'],
                     'built_sha256': actual, 'status': status})
    (output / 'comparison.json').write_text(json.dumps(rows, indent=2) + '\n')
    with (output / 'SHA256SUMS').open('w') as stream:
        for row in rows:
            if row['built_sha256']:
                stream.write(row['built_sha256'] + '  ' + row['path'] + '\n')
    text = ['# Comparison with signed MacRunner 1.0.7 S2', '',
            'Informational report. Compiler, SDK, dependencies, stripping and signing differ.', '',
            '| Output | Status | Release SHA256 | Built SHA256 |', '|---|---|---|---|']
    for row in rows:
        text.append('| ' + row['path'] + ' | ' + row['status'] + ' | ' + row['release_sha256'] +
                    ' | ' + (row['built_sha256'] or 'MISSING') + ' |')
    (output / 'comparison.md').write_text('\n'.join(text) + '\n')
    print(json.dumps({status: sum(row['status'] == status for row in rows)
                      for status in ['MATCH', 'DIFFERENT', 'MISSING']}))

if __name__ == '__main__':
    main()

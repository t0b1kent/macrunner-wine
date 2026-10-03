#!/usr/bin/env python3
"""Repeat published SECRETS-SCAN patterns without printing matched values."""
import collections
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PATTERNS = [
    ('private-key-block', rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----'),
    ('github-token', rb'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b'),
    ('github-fine-grained-pat', rb'\bgithub_pat_[A-Za-z0-9_]{22,}\b'),
    ('openai/anthropic-style-key', rb'\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}\b'),
    ('slack-token', rb'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
    ('aws-access-key-id', rb'\bAKIA[0-9A-Z]{16}\b'),
    ('google-api-key', rb'\bAIza[0-9A-Za-z_-]{35}\b'),
    ('npm/pypi-token', rb'\b(?:npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,})\b'),
    ('bearer-or-basic-literal', rb'(?i)authorization:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}'),
    ('url-with-credentials', rb'\b[a-z][a-z0-9+.-]{2,10}://[^\s/:@"\'<>]{2,40}:[^\s/:@"\'<>]{3,}@[A-Za-z0-9.-]+'),
    ('keychain-cli-reference', rb'security\s+(?:find|add|delete)-(?:generic|internet)-password'),
    ('named-secret-env', rb'\b(?:CF_API_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|NPM_TOKEN)\b'),
]
CFG_EXT = ('.ini','.json','.yaml','.yml','.conf','.cfg','.env','.plist','.toml','.properties',
           '.xml','.sh','.cjs','.py','.txt','.md','.cnf','.reg','.inf','.rb')
PW = re.compile(rb'(?i)\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+_.=-]{8,})["\']?')
NAME_PAT = re.compile(r'(^|/)(\.env(\..*)?|.*credential.*|.*secret.*|final-child\.json|.*\.pem|.*\.key|.*\.p12|.*\.pfx|.*\.keystore|id_rsa.*|id_ed25519.*|\.netrc|\.npmrc|\.pypirc|signing\.key|.*\.jks)$', re.I)
BUILD_EXT = {'.o','.so','.dll','.a','.res','.exe','.dylib','.pdb','.obj','.lib','.pyc','.d'}
BACKUP = re.compile(r'(БЫЛО|BYLO|\.before(?:[.-]|$)|\.orig(?:[.-]|$)|\.bak(?:[.-]|$))', re.I)
PRIVATE_PATH = re.compile(b'/' + b'Users/' + rb'[^\s/]+|' + b'/' + b'Volumes/' + rb'[^\s/]+')
SIGNING = re.compile(rb'(?i)(?:apple[_ -]?id|team[_ -]?id|signing[_ -]?(?:fingerprint|identity))\s*[=:]\s*["\']?[A-Za-z0-9@._-]{8,}')
EMAIL = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
PUBLIC_EMAIL = b'93673987+t0b1kent@users.noreply.github.com'

def main():
    root = Path(__file__).resolve().parent.parent
    output = Path(sys.argv[1])
    upstream = {}
    with (root / 'docs/upstream-manifest.tsv').open() as stream:
        for row in csv.DictReader(stream, delimiter='\t'):
            upstream[row['path']] = row['sha256']
    findings, hygiene, emails = [], [], []
    files = sorted(p for p in root.rglob('*') if p.is_file() and
                   not any(x in {'.git','_build','_install','_toolchain','__pycache__'} for x in p.relative_to(root).parts))
    patterns = [(name, re.compile(pattern)) for name,pattern in PATTERNS]
    for literal in filter(None, os.environ.get('SECRETS_SCAN_EXTRA','').split(',')):
        patterns.append(('operator-supplied-literal', re.compile(re.escape(literal.encode()))))
    for path in files:
        rel = str(path.relative_to(root))
        data = path.read_bytes()
        identical = hashlib.sha256(data).hexdigest() == upstream.get(rel)
        category = 'unmodified-upstream' if identical else 'macrunner-or-modified'
        if NAME_PAT.search(rel):
            findings.append({'path':rel,'pattern':'suspicious-filename','lines':[],'count':1,'category':category})
        for name,pattern in patterns:
            matches = list(pattern.finditer(data))
            if matches:
                findings.append({'path':rel,'pattern':name,'count':len(matches),
                                 'lines':[data.count(b'\n',0,m.start())+1 for m in matches[:5]],'category':category})
        if b'\0' not in data[:4096] and (rel.endswith(CFG_EXT) or path.name == 'Makefile'):
            matches = [m for m in PW.finditer(data) if not re.match(
                rb'^(?:\$|%|@|\{|<|xxx|\*|None|null|true|false|password|passwd|string|value|example|changeme|your|test|dummy)',m.group(2),re.I)]
            if matches:
                findings.append({'path':rel,'pattern':'password-like-literal-in-config','count':len(matches),
                                 'lines':[data.count(b'\n',0,m.start())+1 for m in matches[:5]],'category':category})
        for reason,bad in [('absolute-private-path',bool(PRIVATE_PATH.search(data))),
                           ('signing-personal-id',bool(SIGNING.search(data))),
                           ('backup-filename',bool(BACKUP.search(rel))),
                           ('compiled-output',path.suffix.lower() in BUILD_EXT and path.name != 'COPYING.LIB'),
                           ('oversize',len(data)>50*1024*1024)]:
            if bad:
                hygiene.append({'path':rel,'reason':reason,'category':category})
        other = [m for m in EMAIL.finditer(data) if m.group()!=PUBLIC_EMAIL]
        if other and not identical:
            # Modified upstream files may retain mandatory historical notices.
            old = b''
            if rel in upstream:
                old = subprocess.check_output(['git','-C',str(root),'show','crossover-26.1.0:'+rel])
            inherited = all(m.group() in old for m in other)
            emails.append({'path':rel,'count':len(other),'inherited_upstream_notices':inherited,
                           'lines':[data.count(b'\n',0,m.start())+1 for m in other[:5]]})
    summary = {'files':len(files),'bytes':sum(p.stat().st_size for p in files),
               'max_file_bytes':max(p.stat().st_size for p in files),
               'finding_groups':dict(collections.Counter(x['category'] for x in findings)),
               'hygiene_findings':len(hygiene), 'email_groups':len(emails),
               'skipped_files':0}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps({'summary':summary,'findings':findings,'hygiene':hygiene,
                                  'modified_file_email_review':emails},indent=2)+'\n')
    print(json.dumps(summary))
    return bool(hygiene)

if __name__ == '__main__':
    raise SystemExit(main())

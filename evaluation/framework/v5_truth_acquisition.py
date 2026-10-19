"""Independent CPTC evidence acquisition. Nothing here is imported by production.

Remote terminal/server logs are truth-domain material, never alert inputs.
Windows HTTPS uses the system certificate store, without disabling verification.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'outputs/v5_ground_truth_replay'
TRUTH = OUT / 'truth_domain'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2,
                               allow_nan=False) + '\n', encoding='utf8')


def fetch(url, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Literal single-quoted strings; URLs/paths are controlled, never user code.
    quote = lambda x: "'" + str(x).replace("'", "''") + "'"
    cmd = ('Invoke-WebRequest -Uri ' + quote(url) + ' -OutFile ' + quote(target)
           + ' -TimeoutSec 45 -ErrorAction Stop')
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                            capture_output=True, timeout=55)
    return dict(url=url, path=target.relative_to(ROOT).as_posix(),
                status='ACQUIRED' if result.returncode == 0 else 'FETCH_FAILED',
                sha256=sha(target) if result.returncode == 0 else None,
                bytes=target.stat().st_size if result.returncode == 0 else None,
                error=result.stderr.decode('utf8', errors='replace')[-1500:] if result.returncode else None,
                domain='TRUTH_ONLY', tls_verification='Windows system trust store')


def acquire():
    urls = [('https://mirrors.rit.edu/cptc/', TRUTH / 'indexes/root.html'),
            ('https://mirrors.rit.edu/cptc/cptc3/', TRUTH / 'indexes/cptc3.html')]
    # Fixed source-first selection: all six existing partitions, no candidate scores/IP filters.
    names = ['bash_history.json.gz', 'term.json.gz', 'linux_secure.json.gz',
             'apache_error.json.gz', 'access_combined.json.gz']
    for team in ('t1', 't2', 't5', 't7', 't8', 't9'):
        base = 'https://mirrors.rit.edu/cptc/cptc3/' + team + '/events/'
        urls.append((base, TRUTH / 'indexes' / (team + '.html')))
        for name in names:
            urls.append((base + name, TRUTH / team / name))
    for name in ('osqueryd_results.json.gz', 'osqueryd_results_too_small.json.gz',
                 'server.json.gz', 'postgresql_10_main_too_small.json.gz',
                 'onramp_error_too_small.json.gz', 'error_2.json.gz', 'error_3.json.gz',
                 'error_4.json.gz', 'error_5.json.gz'):
        urls.append(('https://mirrors.rit.edu/cptc/cptc3/t5/events/' + name, TRUTH / 't5' / name))
    for team in ('t1', 't5', 't9'):
        urls.append(('https://mirrors.rit.edu/cptc/cptc3/' + team + '/events/access_too_small.json.gz',
                     TRUTH / team / 'access_too_small.json.gz'))
    def get(pair):
        try:
            return fetch(*pair)
        except Exception as exc:
            return dict(url=pair[0], path=pair[1].relative_to(ROOT).as_posix(),
                        status='FETCH_FAILED', error=str(exc), domain='TRUTH_ONLY')
    rows = list(ThreadPoolExecutor(max_workers=6).map(get, urls))
    save(OUT / 'ground_truth_sources.json', dict(selection='all six existing partitions; fixed evidence filenames; no score/IP selection',
        sources=rows, note='Successful acquisition does not attest attack success or local-export identity.'))
    print(json.dumps(dict(acquired=sum(x['status']=='ACQUIRED' for x in rows), attempted=len(rows))))


def records(path):
    """Splunk export reader in the truth domain only; preserves original rows."""
    with gzip.open(path, 'rt', encoding='utf8') as stream:
        for ordinal, line in enumerate(stream, 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            for row in obj if isinstance(obj, list) else [obj]:
                yield ordinal, row.get('result', row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--acquire', action='store_true')
    args = parser.parse_args()
    if args.acquire:
        acquire()

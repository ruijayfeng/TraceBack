"""Hash-only audit for the Stage chain task; never parse truth contents."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def protected_paths():
    previous = json.loads((ROOT/'outputs/evidence_trace_v1/protected_after.json').read_text(encoding='utf8'))
    paths = {Path(p) for p in previous}
    experiment = next(p for p in paths if p.name == 'attack125_final.jsonl').parent.parent
    paths.update(p for p in experiment.rglob('*') if p.is_file())
    paths.update(p for p in (ROOT/'outputs/evidence_trace_v1').rglob('*') if p.is_file())
    return paths


def capture():
    # Code is protected as well: new task modules may be added, existing ones
    # must remain byte-for-byte unchanged. They are never imported here.
    paths = protected_paths()
    for folder in ('backend', 'scripts', 'configs', 'docs'):
        paths.update(p for p in (ROOT/folder).rglob('*') if p.is_file() and
                     p.suffix in {'.py', '.yaml', '.yml', '.md', '.toml', '.json'} and
                     '__pycache__' not in p.parts)
    paths.add(ROOT/'AGENTS.md')
    return {str(p):sha(p) for p in sorted(paths)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    if args.compare:
        previous = json.loads(args.compare.read_text(encoding='utf8'))
        values = {p:sha(Path(p)) for p in previous}
        # Also catch new/removed files in protected experiment/trace directories.
        assert {str(p) for p in protected_paths()} <= set(previous), 'protected_file_set_changed'
        assert values == previous, 'protected_file_sha256_changed'
    else:
        values = capture()
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(values, indent=2, ensure_ascii=False)+'\n', encoding='utf8')
    print(json.dumps(dict(protected_files=len(values), unchanged=True if args.compare else None)))

"""Hash-only experiment and upstream audit. Does not parse ground truth."""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot():
    previous = json.loads((ROOT/'outputs/evidence_trace_v1/integrity_before.json').read_text(encoding='utf8'))
    paths = {Path(p) for p in previous}
    for folder in ('community_v1', 'behavior_stage_v1', 'stage_relations_v1'):
        directory = ROOT/'outputs'/folder
        manifest = json.loads((directory/'manifest.json').read_text(encoding='utf8'))
        paths.update(p for p in directory.iterdir() if p.is_file())
        for key in ('artifacts', 'source_artifacts'):
            paths.update(ROOT/p for p in manifest.get(key, {}))
    experiment = next(p for p in paths if p.name == 'attack125_final.jsonl').parent.parent
    paths.update(p for p in experiment.rglob('*') if p.is_file())
    return {str(p):digest(p) for p in sorted(paths)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    values = snapshot()
    args.receipt.write_text(json.dumps(values, indent=2, ensure_ascii=False)+'\n', encoding='utf8')
    if args.compare:
        assert values == json.loads(args.compare.read_text(encoding='utf8')), 'protected_files_changed'
    print(json.dumps(dict(protected_files=len(values), unchanged=True if args.compare else None)))

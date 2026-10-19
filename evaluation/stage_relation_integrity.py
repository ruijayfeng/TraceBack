"""Hash-only audit, deliberately outside production. Never parse truth contents."""
import argparse
import hashlib
import json
from pathlib import Path


def snapshot(root, receipt):
    root = Path(root)
    previous = json.loads((root/'outputs/behavior_stage_v1/integrity_before.json').read_text(encoding='utf8'))
    paths = {Path(p) for p in previous}
    # Protect all experiment files, including any additional GT beside the input.
    experiment = next(p for p in paths if p.name == 'attack125_final.jsonl').parent.parent
    paths.update(p for p in experiment.rglob('*') if p.is_file())
    for directory in ('evaluation', 'data/input'):
        for p in (root/directory).rglob('*'):
            if p.is_file() and (p.name.lower() in {'ground_truth.json', 'labels.csv', 'attacks.log', 'gold_chain.json'}):
                paths.add(p)
    manifest = root/'outputs/behavior_stage_v1/manifest.json'
    paths.add(manifest)
    baseline = json.loads(manifest.read_text(encoding='utf8'))
    paths.update(root/p for p in baseline['artifacts'])
    paths.update(p for p in (root/'outputs/behavior_stage_v1').iterdir() if p.is_file())
    hashes = {}
    for path in sorted(paths):
        h = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b''):
                h.update(chunk)
        hashes[str(path)] = h.hexdigest()
    Path(receipt).parent.mkdir(parents=True, exist_ok=True)
    Path(receipt).write_text(json.dumps(hashes, indent=2, ensure_ascii=False)+'\n', encoding='utf8')
    return hashes


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--compare')
    args = parser.parse_args()
    hashes = snapshot(Path(__file__).resolve().parents[1], args.receipt)
    if args.compare:
        before = json.loads(Path(args.compare).read_text(encoding='utf8'))
        assert before == hashes, 'protected_file_set_or_sha256_changed'
    print(json.dumps(dict(protected_files=len(hashes), unchanged=True if args.compare else None)))

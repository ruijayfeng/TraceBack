"""Read-only architecture receipt, before the authorized front-layer edits."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/front_data_layer'


def hashes():
    paths = []
    for folder in ('backend/app', 'configs', 'frontend/src'):
        paths.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / 'before_hashes.json'
    if target.exists():
        raise SystemExit('baseline already recorded')
    target.write_text(json.dumps(hashes(), indent=2) + '\n', encoding='utf8')

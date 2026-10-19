"""Sealed artifact reader; cannot trigger a production run."""
import gzip
import json
from pathlib import Path

from .common import OUT, ROOT, INPUT, THRESHOLD, VERSION, read, sha


def rows(path):
    opener = gzip.open if Path(path).suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf8') as handle:
        for line in handle:
            yield json.loads(line)


def require_sealed(destination=OUT):
    destination = Path(destination)
    manifest = read(destination / 'blind_run_manifest.json')
    if (manifest.get('status') != 'completed' or manifest.get('is_complete') is not True
            or manifest.get('ground_truth_loaded') is not False
            or manifest.get('threshold') != THRESHOLD or manifest.get('algorithm_version') != VERSION):
        raise ValueError('blind_manifest_is_not_complete_and_frozen')
    if not manifest['files']:
        raise ValueError('blind_manifest_has_no_artifacts')
    for name, digest in manifest['files'].items():
        p = (destination / name).resolve()
        if not p.is_relative_to((destination / 'blind').resolve()) or sha(p) != digest:
            raise ValueError('sealed_blind_artifact_mismatch:' + name)
    return manifest

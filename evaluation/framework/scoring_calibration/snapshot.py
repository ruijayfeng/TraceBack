"""New immutable baseline boundary; never updates an earlier seal."""
import hashlib
import json
import shutil
from pathlib import Path
from . import ROOT, BASE, OUT


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                               allow_nan=False) + '\n', encoding='utf8')


def digest_map(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare():
    if OUT.exists():
        raise ValueError('single_use_output_already_exists')
    OUT.mkdir(parents=True)
    previous = read(BASE / 'before_hashes.json')
    protected = dict(previous['dataset']) | dict(previous['generators'])
    protected.update(previous['historical'])
    for folder, pattern in [('backend/app', '*.py'), ('configs', '*.yaml'), ('docs', '*.md')]:
        protected.update({str(p): sha(p) for p in sorted((ROOT / folder).rglob(pattern))})
    protected[str(ROOT / 'AGENTS.md')] = sha(ROOT / 'AGENTS.md')
    # Preserve every completed source-recovery artifact; exclude only temporary test trees.
    import os
    for directory, dirs, files in os.walk(BASE):
        dirs[:] = [d for d in dirs if not d.endswith('_tmp') and d != '__pycache__']
        for name in files:
            p = Path(directory) / name
            protected[str(p)] = sha(p)
    for path, expected in protected.items():
        if sha(path) != expected:
            raise ValueError('baseline_changed:' + path)
    production = {str(p.relative_to(ROOT)): sha(p) for p in sorted((ROOT / 'backend/app').rglob('*.py'))}
    for name in production:
        target = OUT / 'baseline/source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    shutil.copyfile(BASE / 'preparation.json', OUT / 'baseline/effective_configuration.json')
    receipt = read(BASE / 'blind_A/receipt.json')
    if (receipt['candidate_count'], receipt['admitted_count'], receipt['scored_member_pairs']) != (240621, 14788, 241464):
        raise ValueError('unexpected_source_recovery_baseline')
    preparation = read(BASE / 'preparation.json')
    save(OUT / 'baseline/seal.json', dict(
        status='SEALED_BEFORE_CANDIDATE_FORMULAS', protected_files=protected,
        implementation_hash=digest_map(production), implementation_files=production,
        config_hash=preparation['config_hash'], mapping_digest=preparation['mapping_digest'],
        candidate_digest=receipt['candidate_digest'], score_digest=receipt['score_digest'],
        admission_digest=receipt['admission_digest'],
        production_record_config_hash=read(BASE / 'blind_A/record.json')['config_hash'],
        baseline_counts=receipt, limitations=read(BASE / 'regression_summary.json'),
        archived_member_decomposition_reference=str(BASE / 'blind_A/diagnostics.jsonl.gz'),
        archived_member_decomposition_sha256=protected[str(BASE / 'blind_A/diagnostics.jsonl.gz')],
        no_prior_seal_overwritten=True))
    print('BASELINE_SEALED', len(protected), receipt['candidate_digest'], flush=True)


def verify():
    seal = read(OUT / 'baseline/seal.json')
    changed = [p for p, h in seal['protected_files'].items() if not Path(p).is_file() or sha(p) != h]
    if changed:
        raise ValueError({'protected_files_changed': changed})
    return dict(protected_file_count=len(seal['protected_files']), changed=[],
                dataset_unchanged=True, gt_unchanged=True, generator_unchanged=True,
                adapter_unchanged=True, projection_unchanged=True, candidate_policy_unchanged=True,
                production_scorer_unchanged=True, production_admission_policy_unchanged=True,
                previous_seals_unchanged=True)


if __name__ == '__main__':
    prepare()

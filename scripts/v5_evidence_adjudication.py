"""Offline V5 adjudication driver. No domain persistence or production changes.

Run --prepare first, inspect blind_review.jsonl, then --finish. Labels are
score-independent agent judgements, never advertised as independent human GT.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import v5_design_diagnostic as d
import v5_evidence_validation as previous
import v5_validation_evidence as ev

OUT = ROOT / 'outputs/v5_evidence_adjudication'
PRIOR = ROOT / 'outputs/v5_evidence_validation'
DESIGN = ROOT / 'outputs/v5_design_diagnostic'
VERSION = 'v5-evidence-adjudication-1'


def save(name, value):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    d.atomic_json(path, value)


def lines(name, rows):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf8', newline='\n') as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + '\n')


def freeze():
    """Validate immutable historical receipts before any data-dependent work."""
    OUT.mkdir(parents=True, exist_ok=True)
    mismatches = []
    checked = {}
    baseline = d.read(PRIOR / 'protected_before.json')
    for path, expected in baseline.items():
        actual = d.file_digest(ROOT / path) if (ROOT / path).is_file() else None
        checked[path] = actual
        if actual != expected:
            mismatches.append(dict(path=path, expected=expected, actual=actual))
    for folder in (PRIOR, DESIGN):
        manifest = d.read(folder / 'manifest.json')
        for name, expected in manifest['files'].items():
            path = folder / name
            actual = d.file_digest(path) if path.is_file() else None
            checked[path.relative_to(ROOT).as_posix()] = actual
            if actual != expected:
                mismatches.append(dict(path=str(path), expected=expected, actual=actual))
        for name, expected in manifest.get('source_hashes', {}).items():
            actual = d.file_digest(ROOT / name) if (ROOT / name).is_file() else None
            if actual != expected:
                mismatches.append(dict(path=name, expected=expected, actual=actual))
    # Protect frontend and all production/config files as well as baseline docs.
    for base in ('backend/app', 'configs', 'frontend/src'):
        for path in sorted((ROOT / base).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts:
                checked[path.relative_to(ROOT).as_posix()] = d.file_digest(path)
    start = OUT / 'protected_before.json'
    if start.exists():
        before = d.read(start)
        for path in sorted(set(before) | set(checked)):
            if before.get(path) != checked.get(path):
                mismatches.append(dict(path=path, expected=before.get(path), actual=checked.get(path)))
    config = None
    try:
        config, receipt, receipt_path = d.load_frozen_config()
        old = d.read(PRIOR / 'frozen_state.json')
        for key, actual in dict(algorithm_version=d.correlation_version(config),
                v4_config_hash=config.config_hash, mapping_digest=config.mapping_digest,
                threshold=config.algorithm.score.correlation_threshold).items():
            if actual != old[key]:
                mismatches.append(dict(field=key, expected=old[key], actual=actual))
        import yaml
        if yaml.safe_load((DESIGN / 'diagnostic_policy.yaml').read_text(encoding='utf8')) != d.design():
            mismatches.append(dict(field='diagnostic_formula', actual='code_policy_diverged'))
    except Exception as exc:
        mismatches.append(dict(field='frozen_recipe', error=str(exc)))
    result = dict(status='FAIL' if mismatches else 'PASS', mismatches=mismatches,
        algorithm_version=d.correlation_version(config) if config else None,
        config_hash=config.config_hash if config else None,
        mapping_digest=config.mapping_digest if config else None,
        threshold=config.algorithm.score.correlation_threshold if config else None,
        candidate_recipe=config.algorithm.candidate.model_dump(mode='json') if config else None,
        candidate_contract='v1.1; original non-time Top-K and budgets unchanged',
        input_dataset_hashes={p:h for p,h in checked.items() if p.startswith('data/')},
        previous_evidence_validation_manifest_hash=d.file_digest(PRIOR / 'manifest.json'),
        diagnostic_manifest_hash=d.file_digest(DESIGN / 'manifest.json'),
        frozen_v4_receipt_hash=d.file_digest(ROOT / 'outputs/correlation_v4_small/FREEZE_MANIFEST.json'),
        protected_file_count=len(checked), production_v4_modified='NO' if not mismatches else 'UNKNOWN',
        production_v5_implemented='NO', git_status='UNAVAILABLE_NO_GIT_METADATA')
    save('freeze_verification.json', result)
    if mismatches:
        save('manifest.json', dict(task_result='V5_ADJUDICATION_BLOCKED_FREEZE_MISMATCH', freeze=result))
        raise RuntimeError('TASK_RESULT=V5_ADJUDICATION_BLOCKED_FREEZE_MISMATCH')
    if not start.exists():
        save('protected_before.json', checked)
    return config


def targets():
    audit = d.read(PRIOR / 'uncertain_high_score_audit.json')
    rows = audit['cards']
    if len(rows) != 94 or len({r['candidate_id'] for r in rows}) != 94:
        raise ValueError('exact_94_original_targets_required')
    if sum(r['prototypes']['b']['admitted'] for r in rows) != 26:
        raise ValueError('exact_26_original_B_admitted_required')
    return rows


def dataset(name):
    if name != 'cptc_t5_dev_10k':
        return previous.ait_dataset(name)
    ingestion = d.load_cptc_dataset(ROOT).config
    recipe = d.read(ROOT / 'outputs/cptc_2018_step3a_t5/recipe.json')
    settings = {k:d.AdapterSettings(**v) for k,v in recipe['config_snapshot']['sources'].items()}
    adapter = d.SuricataAdapter(ingestion, next(iter(settings.values())))
    alerts, locators = [], {}
    for rec in d.read_cptc_file(d.DEV):
        if rec.error:
            raise ValueError(rec.error)
        a = adapter.convert(rec.eve)
        alerts.append(a)
        locators[a.alert_id] = dict(path=d.DEV.relative_to(ROOT).as_posix(), ordinal=rec.ordinal,
            raw_fingerprint=a.raw_fingerprint, source_namespace=a.source_namespace)
    return alerts, settings, locators, dict(raw_count=len(alerts), selected_count=len(alerts),
        input_hashes={d.DEV.relative_to(ROOT).as_posix():d.file_digest(d.DEV)})


def alert_evidence(a, locator):
    card = ev.alert_card(a)
    card.update(raw_alert=a.raw_alert, raw_excerpt=a.raw_alert, locator=locator,
        canonical=a.model_dump(mode='json'), detector_metadata=(
            a.raw_alert.get('AnalysisComponent') or a.raw_alert.get('alert') or a.raw_alert.get('rule')))
    return card


def prepare():
    freeze()
    rows = targets()
    needed = {aid for row in rows for aid in row['pair']}
    evidence, manifests = {}, {}
    with d.truth_guard(ROOT):
        for name in ('cptc_t5_dev_10k', 'russellmitchell_dev_small', 'fox_validation_small'):
            alerts, settings, locators, meta = dataset(name)
            expected = d.read(PRIOR / 'dataset_profiles.json')['scored_slices'][name]
            digest = d.content_digest(sorted([a.alert_id, a.raw_fingerprint] for a in alerts))
            if digest != expected['selected_identity_digest']:
                raise ValueError('slice_identity_changed:' + name)
            lines('cache/' + name + '.jsonl', (dict(dataset=name,
                alert=a.model_dump(mode='json'), locator=locators[a.alert_id]) for a in sorted(alerts, key=lambda x:x.alert_id)))
            manifests[name] = dict(**meta, canonical_count=len(alerts), selected_identity_digest=digest,
                source_settings={k:v.snapshot() for k,v in settings.items()})
            for a in alerts:
                if a.alert_id in needed:
                    evidence[a.alert_id] = alert_evidence(a, locators[a.alert_id])
            d.log('adjudication_prepare', dataset=name, count=len(alerts), identity_verified=True)
    if set(evidence) != needed:
        raise ValueError('missing_target_raw_alert')
    blind = []
    for row in sorted(rows, key=lambda r:r['candidate_id']):
        a,b = (evidence[aid] for aid in row['pair'])
        for old,new in zip((row['alert_a'],row['alert_b']), (a,b)):
            if old['raw_fingerprint'] != new['raw_fingerprint']:
                raise ValueError('target_raw_changed')
        blind.append(dict(pair_id=row['candidate_id'], dataset=row['dataset'], alert_a=a, alert_b=b))
    lines('blind_review.jsonl', blind)
    save('input_manifest.json', manifests)
    # Read all preceding evidence artifacts; retain structural inventory and hashes.
    inventory = {}
    for folder in (PRIOR, DESIGN):
        for path in sorted(folder.glob('*')):
            if not path.is_file():
                continue
            item = dict(sha256=d.file_digest(path), bytes=path.stat().st_size)
            if path.suffix == '.json':
                value = d.read(path)
                item.update(json_type=type(value).__name__,
                    members={k:len(v) if isinstance(v,(list,dict)) else v for k,v in value.items()}
                        if isinstance(value,dict) else len(value))
            elif path.suffix == '.jsonl':
                count = 0
                with path.open(encoding='utf8') as stream:
                    for line in stream:
                        json.loads(line)
                        count += 1
                item['rows_validated'] = count
            inventory[path.relative_to(ROOT).as_posix()] = item
    save('prior_artifact_inventory.json', inventory)
    d.log('prepared', total_target_pairs=94, admitted_target_pairs=26,
        blind_review_hash=d.file_digest(OUT / 'blind_review.jsonl'))


def cached():
    from app.models import CanonicalAlert
    for path in sorted((OUT / 'cache').glob('*.jsonl')):
        with path.open(encoding='utf8') as stream:
            for line in stream:
                row = json.loads(line)
                yield row['dataset'], CanonicalAlert.model_validate(row['alert']), row['locator']


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--finish', action='store_true')
    args = parser.parse_args()
    if args.prepare:
        prepare()
    if args.finish:
        freeze()
        from v5_evidence_adjudication_report import finish
        finish()
        freeze()


if __name__ == '__main__':
    main()

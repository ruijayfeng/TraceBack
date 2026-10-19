"""Read-only input inventory and explicit, immutable evaluation configuration."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
DATASET = Path(r'D:\Code_WorkSpace\TraceBack-Dataset')
BASE = DATASET / 'data/traceback_semisynthetic_v1'
INPUT = BASE / 'final/traceback_demo_v1.jsonl'
OUT = ROOT / 'outputs/v4_semisynthetic_baseline'
VERSION = 'alert-correlation-v4-role-context-candidate-v1.1'
EXPECTED_HASH = '1f82b45962095d806af22463bcec35e0709b11b1a6e123e4b81d75c8521b984d'
MAPPING = 'aba87d612711cc4cb67998df9604b62b61a3fb72b01c165d1745594b8a538658'
THRESHOLD = .65
sys.path.insert(0, str(ROOT / 'backend'))


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                               allow_nan=False) + '\n', encoding='utf8')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def inventory(root, *, production=False):
    root = Path(root)
    files = []
    if production:
        for name in ('backend/app', 'configs', 'docs', 'frontend/src'):
            files.extend(p for p in (root / name).rglob('*') if p.is_file()
                         and '__pycache__' not in p.parts)
        files.append(root / 'AGENTS.md')
    else:
        # Include .git and pre-existing bytecode; never run Python in the dataset repo.
        files = [p for p in root.rglob('*') if p.is_file()]
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(files)}


def verify_inventory(root, before, *, production=False):
    after = inventory(root, production=production)
    differences = {k: {'before': before.get(k), 'after': after.get(k)}
                   for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)}
    return {'status': 'FAIL' if differences else 'PASS', 'file_count': len(after),
            'differences': differences}


def frozen_config():
    # Existing validator includes the formally accepted execution equivalence receipt.
    sys.path.insert(0, str(ROOT / 'scripts'))
    from cptc_2018_step3a import load_frozen_config
    from app.correlation.edges import correlation_version
    config, receipt, path = load_frozen_config()
    if (correlation_version(config) != VERSION or config.mapping_digest != MAPPING
            or config.algorithm.score.correlation_threshold != THRESHOLD
            or receipt['threshold'] != THRESHOLD):
        raise ValueError('frozen_version_mapping_or_threshold_mismatch')
    return config, receipt, path


def prepare():
    if (OUT / 'blind_run_manifest.json').exists():
        raise RuntimeError('blind output already exists; use evaluate/verify, never replay after GT')
    OUT.mkdir(parents=True, exist_ok=True)
    save(OUT / 'dataset_before.json', inventory(DATASET))
    save(OUT / 'production_before.json', inventory(ROOT, production=True))
    config, receipt, path = frozen_config()
    manifest_path = BASE / 'final/traceback_demo_v1_manifest.json'
    manifest = read(manifest_path)
    # Only declared ingestion metadata enters the worker. No scenario, provenance,
    # memberships, attack time range or labels enter preparation.json.
    expected_counts = dict(total_count=10051, real_background_count=10000,
                           synthetic_attack_count=21, hard_negative_count=30,
                           ground_truth_node_count=7, ground_truth_edge_count=6)
    for key, value in expected_counts.items():
        if manifest[key] != value:
            raise ValueError('dataset_manifest_count_mismatch:' + key)
    if sha(INPUT) != manifest['final_file_sha256']:
        raise ValueError('dataset_manifest_input_hash_mismatch')
    from app.adapters.base import AdapterSettings
    from app.utils.stable_id import content_digest
    settings = {}
    for ns in manifest['source_namespaces']:
        if ns not in {'suricata', 'wazuh.host', 'wazuh.authentication'}:
            raise ValueError('unsupported_declared_source_namespace')
        settings[ns] = AdapterSettings(source_namespace=ns,
            format_profile='suricata_eve_v1' if ns == 'suricata' else 'wazuh_json_v1',
            generator='Suricata' if ns == 'suricata' else 'Wazuh').snapshot()
    combined = content_digest({'algorithm': config.snapshot, 'sources': settings})
    save(OUT / 'preparation.json', {'input': str(INPUT), 'input_sha256': sha(INPUT),
        'algorithm': config.snapshot, 'sources': settings})
    # Distinguish three hash domains instead of claiming a different deployment
    # recipe has the historical CPTC-only run hash.
    historical = read(ROOT / 'outputs/cptc_2018_step3a_t5/recipe.json')
    if historical['config_hash'] != EXPECTED_HASH:
        raise ValueError('historical_cptc_recipe_hash_mismatch')
    save(OUT / 'freeze_verification.json', {'status': 'PASS', 'algorithm_version': VERSION,
        'threshold': THRESHOLD, 'mapping_digest': config.mapping_digest,
        'algorithm_config_hash': config.config_hash, 'run_config_hash': combined,
        'expected_historical_run_config_hash': EXPECTED_HASH,
        'historical_recipe_sha256': sha(ROOT / 'outputs/cptc_2018_step3a_t5/recipe.json'),
        'formal_freeze_receipt': str(path), 'formal_freeze_receipt_sha256': sha(path),
        'receipt_config_hash': receipt['config_hash'],
        'hash_difference_reason': 'Historical hash includes CPTC-only source settings; this run uses the three dataset-declared namespaces. Algorithm snapshot and mappings are unchanged.',
        'scope_policy': 'No shared network/asset/account/session scope or alias was declared; retain production namespace fallback. All timestamps carry UTC offsets; no timezone inference.',
        'manifest_path': str(manifest_path), 'manifest_sha256': sha(manifest_path),
        'preflight_counts_from_manifest': expected_counts,
        'ground_truth_semantically_loaded': False,
        'integrity_note': 'Before-run opaque SHA-256 reads inventory every dataset file, including GT, without parsing or exposing its content to the worker.'})


def integrity():
    result = {'dataset': verify_inventory(DATASET, read(OUT / 'dataset_before.json')),
              'production': verify_inventory(ROOT, read(OUT / 'production_before.json'), production=True)}
    save(OUT / 'integrity_verification.json', result)
    if any(v['status'] != 'PASS' for v in result.values()):
        raise ValueError('protected_files_changed')
    return result

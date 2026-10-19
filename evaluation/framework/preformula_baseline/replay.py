"""Frozen preparation, fresh blind replay, seal verification; no GT imports."""
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

from . import ROOT, OUT, PREVIOUS, VERSION
from .boundary import development_config, verify_current
from .audit import verify_history
from evaluation.framework.v4_semisynthetic_baseline.common import DATASET, INPUT, read, save, sha, verify_inventory


def freeze():
    from app.utils.stable_id import content_digest
    if (OUT / 'freeze_receipt.json').exists(): raise ValueError('baseline_is_immutable')
    previous = read(PREVIOUS / 'preparation.json')
    formulas = previous['formula_components']
    # The sole edges.py change is dispatching an explicit execution identity.
    # Compare every other AST node against the exact previous source bytes hash.
    version_branch = ("    if config.algorithm.implementation_version == 'v5-preformula-candidate-v1':\n"
                      "        return 'alert-correlation-v5-preformula-candidate-v1'\n")
    edge_path = 'backend/app/correlation/edges.py'
    edge_bytes = (ROOT / edge_path).read_bytes()
    branch_bytes = version_branch.replace('\n', '\r\n').encode() if b'\r\n' in edge_bytes else version_branch.encode()
    reverted = edge_bytes.replace(branch_bytes, b'', 1)
    if reverted == edge_bytes or hashlib.sha256(reverted).hexdigest() != formulas[edge_path]:
        raise ValueError('edges_change_exceeds_version_identity')
    for p, h in formulas.items():
        if p != edge_path and sha(ROOT / p) != h:
            raise ValueError('frozen_score_formula_changed:' + p)
    # Projection/candidate repair implementations must remain exactly as accepted.
    repair_files = ('backend/app/adapters/base.py', 'backend/app/adapters/wazuh.py',
        'backend/app/adapters/wazuh_semantics.py', 'backend/app/entities/extraction.py',
        'backend/app/correlation/entity_bridges.py', 'backend/app/correlation/candidates.py',
        'backend/app/correlation/index.py')
    for p in repair_files:
        if sha(ROOT / p) != previous['implementation_before_blind'][p]:
            raise ValueError('accepted_projection_candidate_repair_changed:' + p)
    config, _, _ = development_config()
    from app.correlation.edges import correlation_version
    if correlation_version(config) != VERSION or config.algorithm.score.correlation_threshold != .65:
        raise ValueError('preformula_version_or_threshold_mismatch')
    old = previous['algorithm']
    restored = config.snapshot
    restored.pop('implementation_version')
    if restored != old: raise ValueError('algorithm_parameters_changed')
    implementation = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted((ROOT/'backend/app').rglob('*'))
                      if p.is_file() and '__pycache__' not in p.parts}
    configs = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted((ROOT/'configs').rglob('*.yaml'))}
    mappings = {p: h for p, h in configs.items() if p.startswith('configs/mappings/')}
    deployment = ROOT / 'evaluation/configs/v5_preformula_deployment.yaml'
    configs[deployment.relative_to(ROOT).as_posix()] = sha(deployment)
    run_hash = content_digest({'algorithm': config.snapshot, 'sources': previous['sources']})
    before = read(OUT / 'integration_before.json')
    if verify_inventory(DATASET, before['dataset_files'])['status'] != 'PASS': raise ValueError('dataset_changed')
    verify_history()
    receipt = {'baseline_name': 'V5_PRE_FORMULA_BASELINE', 'algorithm_version': VERSION,
        'created_at': datetime.now(timezone.utc).isoformat(), 'git_commit_if_available': None,
        'git_commit_status': 'not_a_git_repository', 'config_hash': run_hash,
        'algorithm_config_hash': config.config_hash, 'mapping_digest': config.mapping_digest,
        'projection_contract_version': 'role-aware-v1', 'candidate_policy_version': 'v1.1-role-compatible-bridges-v1',
        'score_formula_version': 'frozen-v4-role-context', 'score_formula_modified': False,
        'projection_candidate_semantics_equal_historical_v4': False, 'production_v5_formula': False,
        'threshold': .65, 'implementation_file_hashes': implementation,
        'configuration_file_hashes': configs, 'mapping_hashes': mappings,
        'implementation_digest': content_digest(implementation),
        'dataset_identity': {'input_sha256': sha(INPUT), 'input_file': INPUT.name,
                             'split': 'semi-synthetic-development', 'read_only': True,
                             'inventory_sha256': content_digest(before['dataset_files'])},
        'ground_truth_not_runtime_input': True, 'formula_file_hashes': formulas,
        'edges_identity_only_change_verified': True,
        'accepted_repairs_file_hashes': {p: sha(ROOT / p) for p in repair_files}}
    save(OUT / 'preparation.json', {'input': str(INPUT), 'input_sha256': sha(INPUT),
        'algorithm': config.snapshot, 'sources': previous['sources'], 'run_config_hash': run_hash})
    for p in implementation:
        dest = OUT / 'implementation_snapshot' / p
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / p, dest)
    save(OUT / 'freeze_receipt.json', receipt)
    print(json.dumps({k: receipt[k] for k in ('algorithm_version', 'config_hash', 'implementation_digest', 'threshold')}))


def blind():
    receipt = verify_current()
    from evaluation.framework.v4_semisynthetic_baseline import blind as worker
    worker.OUT, worker.VERSION = OUT, VERSION
    worker.run()
    manifest = read(OUT / 'blind_run_manifest.json')
    record = read(OUT / 'blind/correlation_record.json')
    if record['algorithm_version'] != VERSION or record['config_hash'] != receipt['config_hash']:
        raise ValueError('prediction_identity_not_preformula')
    manifest.update(baseline_name=receipt['baseline_name'], preparation_sha256=sha(OUT/'preparation.json'),
        freeze_receipt_sha256=sha(OUT/'freeze_receipt.json'), dataset_read_only=True)
    save(OUT / 'blind_run_manifest.json', manifest)


def seal():
    manifest = read(OUT / 'blind_run_manifest.json')
    if (manifest.get('algorithm_version') != VERSION or manifest.get('status') != 'completed'
            or manifest.get('is_complete') is not True or manifest.get('ground_truth_loaded') is not False
            or manifest.get('threshold') != .65 or not manifest.get('files')):
        raise ValueError('not_a_completed_preformula_prediction')
    for key, path in (('freeze_receipt_sha256', OUT/'freeze_receipt.json'), ('preparation_sha256', OUT/'preparation.json')):
        if manifest[key] != sha(path): raise ValueError('sealed_preparation_changed')
    for name, h in manifest['files'].items():
        path = (OUT / name).resolve()
        if not path.is_relative_to((OUT / 'blind').resolve()) or sha(path) != h:
            raise ValueError('sealed_prediction_changed:' + name)
    verify_current()
    return manifest


def permutation():
    """Candidate-only replay of a permuted sealed input, before any GT read."""
    from collections import Counter
    import random
    from app.adapters.base import AdapterSettings
    from app.correlation.candidates import generate_candidates
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.models import CanonicalAlert, DedupeGroup, Entity
    from app.utils.stable_id import canonical_json
    from evaluation.framework.v4_semisynthetic_baseline.artifacts import rows
    from evaluation.framework.v4_semisynthetic_baseline.blind import replay_guard
    if (OUT / 'evaluation_started.json').exists(): raise ValueError('permutation_must_precede_truth')
    seal()
    prepared = read(OUT / 'preparation.json')
    cfg, _, _ = development_config()
    settings = {k: AdapterSettings(**v) for k, v in prepared['sources'].items()}
    aa = [CanonicalAlert.model_validate(r) for r in rows(OUT/'blind/canonical.jsonl.gz')]
    groups = [DedupeGroup.model_validate(r) for r in rows(OUT/'blind/dedupe.jsonl.gz')]
    ee = [Entity.model_validate(r) for r in rows(OUT/'blind/entities.jsonl.gz')]
    digest = hashlib.sha256()
    for r in rows(OUT/'blind/diagnostics.jsonl.gz'):
        if r['stage'] == 'candidate': digest.update(canonical_json(r).encode() + b'\n')
    expected = digest.hexdigest()
    for seq in (aa, groups, ee): random.Random(314159).shuffle(seq)
    digest = hashlib.sha256()
    # Restrict reads during candidate replay exactly as during the primary run.
    with replay_guard(prepared['input'], OUT/'blind') as (events, reads):
        idx = AlertIndex(aa, groups, ee)
        scorer = CorrelationScorer(idx, cfg, settings)
        candidates = generate_candidates(idx, cfg, scorer)
        for candidate in candidates.pairs:
            row = {'stage': 'candidate', 'candidate_contract_version': 'v1.1',
                'admission_reason': 'non_time_window_and_deterministic_top_k',
                'ranking_key': candidate.priority, 'support_key': list(candidate.support_key),
                'channels': list(candidate.channels), 'candidate_reasons': list(candidate.channels),
                'evidence': [e.json_data() for e in candidate.evidence]}
            # Match the production diagnostic sink's JSON tuple->array transport.
            digest.update(canonical_json(json.loads(json.dumps(row))).encode() + b'\n')
    result = {'status': 'PASS' if expected == digest.hexdigest() else 'FAIL',
        'seed': 314159, 'candidate_count': len(candidates.pairs),
        'original_digest': expected, 'permuted_digest': digest.hexdigest(),
        'compared': 'Full ordered candidates, provenance, ranking, windows, hot flags and Top-K metadata',
        'ground_truth_loaded': False, 'rejected_reads': events,
        'resource_truncated_count': candidates.resource_truncated_count}
    save(OUT/'permutation.json', result)
    if result['status'] != 'PASS': raise ValueError('candidate_permutation_regression')

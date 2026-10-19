"""Read a sealed Stage snapshot and stop after Stage pair decisions.

No ingress, extraction, aggregation, AI, truth or chain reconstruction calls.
Integrity receipts involving truth are produced by evaluation separately.
"""
import argparse
import builtins
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.adapters.base import AdapterSettings
from app.community.config import CommunityConfig
from app.community.models import IncidentCandidate
from app.models import CanonicalAlert, Entity
from app.stages.models import Stage, StageResult, BehaviorAnnotation
from app.stage_relations import analyze_stage_relations, load_relation_config, StageRelation
from app.utils.stable_id import canonical_json, content_digest, id_for


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(data)+'\n', encoding='utf8')


@contextmanager
def production_guard(writable_roots):
    """Trap truth/downstream access and protect all existing experiment inputs."""
    old_builtin, old_io, old_import = builtins.open, io.open, builtins.__import__
    counts = dict(guarded_io_calls=0, prohibited_reads=0, prohibited_imports=0)
    def check(path, mode='r', *args, **kwargs):
        if isinstance(path, (str, bytes, Path)):
            p = Path(path.decode() if isinstance(path, bytes) else path).resolve()
            parts = {part.casefold() for part in p.parts}
            if parts & {'evaluation', 'ground_truth', 'historical_gt', 'archive'} or p.name.casefold() in {'ground_truth.json', 'labels.csv', 'gold_chain.json', 'attacks.log'}:
                counts['prohibited_reads'] += 1
                raise AssertionError('production_truth_access_forbidden')
            if any(char in mode for char in 'wax+') and not any(p.is_relative_to(root) for root in writable_roots):
                raise AssertionError('production_write_outside_new_relation_outputs')
            counts['guarded_io_calls'] += 1
    def builtin(path, mode='r', *args, **kwargs):
        check(path, mode)
        return old_builtin(path, mode, *args, **kwargs)
    def io_open(path, mode='r', *args, **kwargs):
        check(path, mode)
        return old_io(path, mode, *args, **kwargs)
    def importing(name, *args, **kwargs):
        if name == 'evaluation' or name.startswith(('evaluation.', 'app.chains', 'app.ai.explanation', 'app.ai.report')):
            counts['prohibited_imports'] += 1
            raise AssertionError('production_truth_or_downstream_import_forbidden')
        return old_import(name, *args, **kwargs)
    builtins.open, io.open, builtins.__import__ = builtin, io_open, importing
    try:
        yield counts
    finally:
        builtins.open, io.open, builtins.__import__ = old_builtin, old_io, old_import


def execute(baseline_manifest, native_input, output):
    baseline_manifest, native_input, output = map(lambda p:Path(p).resolve(), (baseline_manifest, native_input, output))
    if not output.is_relative_to(ROOT/'outputs') or output.exists():
        raise ValueError('relation_output_requires_new_directory_inside_outputs')
    # Compute output identity from a verified manifest and independent policy.
    policy_path = ROOT/'configs/stage-relations-v1.yaml'
    with production_guard([]):
        baseline_hash = sha(baseline_manifest)
        baseline = json.loads(baseline_manifest.read_text(encoding='utf8'))
        if baseline['status'] != 'sealed' or baseline['algorithm_version'] != 'behavior-stage-v1':
            raise ValueError('requires_sealed_stage_snapshot')
        policy = load_relation_config(policy_path)
        input_hash = sha(native_input)
        if input_hash != baseline['input_sha256']:
            raise ValueError('native_input_does_not_match_sealed_stage_input')
        stage_refs = [ref for ref in baseline['artifacts'] if ref.endswith('/stages.jsonl.gz')]
        if len(stage_refs) != 1:
            raise ValueError('requires_one_sealed_stage_artifact')
        stage_path = (ROOT/stage_refs[0]).resolve()
        if not stage_path.is_relative_to(ROOT/'data/processed'/baseline['analysis_id']) or sha(stage_path) != baseline['artifacts'][stage_refs[0]]:
            raise ValueError('invalid_sealed_stage_artifact')
        with gzip.open(stage_path, 'rt', encoding='utf8') as stream:
            input_alert_ids = sorted(aid for line in stream for aid in json.loads(line)['alert_ids'])
    config_snapshot = dict(stage_relations=policy.model_dump(mode='json'),
        community=baseline['config_snapshot']['community'], sources=baseline['config_snapshot']['sources'],
        stage_snapshot_manifest_sha256=baseline_hash)
    config_hash = content_digest(config_snapshot)
    # IDs use immutable content, never a path or wall clock.
    analysis_id = id_for('AnalysisRecord', dict(input_alert_ids=input_alert_ids, config_hash=config_hash,
        algorithm_version=policy.version, schema_version='1.0'))
    domain, detail = ROOT/'data/processed'/analysis_id, ROOT/'outputs/analyses'/analysis_id
    if domain.exists() or detail.exists():
        raise ValueError('relation_snapshot_already_exists')
    with production_guard([output, domain, detail]) as access:
        refs = baseline['artifacts']
        source_files = {}
        def read(name, model):
            found = [ref for ref in refs if ref.endswith('/'+name)]
            if len(found) != 1:
                raise ValueError('sealed_artifact_missing_or_ambiguous:'+name)
            path = (ROOT/found[0]).resolve()
            if not path.is_relative_to(ROOT/'data/processed'/baseline['analysis_id']):
                raise ValueError('sealed_artifact_outside_stage_snapshot')
            if sha(path) != refs[found[0]]:
                raise ValueError('sealed_artifact_hash_mismatch:'+name)
            source_files[found[0]] = refs[found[0]]
            with gzip.open(path, 'rt', encoding='utf8') as stream:
                return [model.model_validate_json(line) for line in stream]
        alerts = read('stage_source_alerts.jsonl.gz', CanonicalAlert)
        entities = read('stage_source_entities.jsonl.gz', Entity)
        communities = read('stage_source_communities.jsonl.gz', IncidentCandidate)
        behaviors = read('behaviors.jsonl.gz', BehaviorAnnotation)
        stages = read('stages.jsonl.gz', Stage)
        stage_result = StageResult(config_hash=content_digest(baseline['config_snapshot']['behavior_stage']), behaviors=behaviors,
            stages=stages, diagnostics=[], statistics={})
        settings = {k:AdapterSettings(**v) for k,v in baseline['config_snapshot']['sources'].items()}
        community_config = CommunityConfig.model_validate(baseline['config_snapshot']['community'])
        result = analyze_stage_relations(stage_result, alerts, entities, communities, settings, community_config, policy)
        if sha(native_input) != input_hash or sha(baseline_manifest) != baseline_hash or any(sha(ROOT/p) != h for p,h in source_files.items()):
            raise ValueError('frozen_input_changed_during_analysis')
        domain.mkdir(parents=True)
        (domain/'stage_relations.jsonl').write_text(''.join(r.canonical_json()+'\n' for r in result.relations), encoding='utf8')
        save(output/'relations.json', [r.model_dump(mode='json') for r in result.relations])
        save(output/'result.json', result.model_dump(mode='json'))
        detail.mkdir(parents=True)
        (detail/'diagnostics.jsonl').write_text(''.join(canonical_json(d)+'\n' for d in result.diagnostics), encoding='utf8')
        save(detail/'frequency_snapshot.json', dict(stages_per_community={c.community_id:sum(s.community_id == c.community_id for s in stages) for c in communities}))
        save(output/'contracts.json', dict(StageRelation=StageRelation.model_json_schema()))
        save(output/'stages.json', [s.model_dump(mode='json') for s in sorted(stages,key=lambda s:s.stage_id)])
        receipt = {p.relative_to(ROOT).as_posix():sha(p) for p in sorted((ROOT/'backend/app/stage_relations').glob('*.py'))}
        receipt['configs/stage-relations-v1.yaml'] = sha(policy_path)
        receipt['scripts/run_stage_level_analysis.py'] = sha(Path(__file__))
        save(output/'implementation_receipt.json', receipt)
        summary = dict(TASK_RESULT='SUCCESS', **result.statistics, DATA_MUTATED=False,
            GROUND_TRUTH_USED_BY_PRODUCTION=False, COMMUNITY_BASELINE_UNCHANGED=True,
            BEHAVIOR_BASELINE_UNCHANGED=True, STAGE_BASELINE_UNCHANGED=True,
            **access)
        save(output/'summary.json', summary)
        artifacts = {p.relative_to(ROOT).as_posix():sha(p) for folder in (domain,detail,output)
                     for p in sorted(folder.iterdir()) if p.is_file()}
        manifest = dict(analysis_id=analysis_id, status='sealed', algorithm_version=policy.version,
            config_hash=config_hash, config_snapshot=config_snapshot, relation_config_hash=result.config_hash,
            input_digest=result.input_digest,
            input_sha256=input_hash, stage_manifest_sha256=baseline_hash, source_artifacts=source_files,
            artifacts=artifacts, summary=summary,
            limitations=['Heuristic primary-evidence strengths and 30 second reversal tolerance are uncalibrated.',
                         'Equal-ranked opposing semantic directions retain an undirected relation with direction_conflict=true.',
                         'Weak evidence with overlapping Stage windows yields NO_RELATION; evidence retained in diagnostics.'])
        save(detail/'manifest.json', manifest)
        save(output/'manifest.json', manifest)
        print(json.dumps(summary, indent=2))
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-manifest', type=Path, default=ROOT/'outputs/behavior_stage_v1/manifest.json')
    parser.add_argument('--native-input', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'outputs/stage_relations_v1')
    args = parser.parse_args()
    execute(args.baseline_manifest, args.native_input, args.output)

"""Run existing native ingress/community building, then semantics and Stage only.

Input must be unannotated alerts. Integrity auditing is a separate hash-only
operation: no evaluation files or their contents enter this pipeline.
"""
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))

from app.adapters.base import AdapterSettings
from app.adapters.multisource import MultiSourceAdapter
from app.ai.provider import load_provider_config
from app.community import load_community_config, prepare_communities
from app.config import load_config, read_yaml
from app.noise_filter import load_noise_config
from app.stages import aggregate_stages, load_stage_config, VOCABULARY
from app.stages.aggregation import STAGE_BUILDER_VERSION
from app.stages.resolver import AISemanticResolver
from app.utils.stable_id import content_digest, id_for
from run_community_builder import sha, save, write_models


def execute(input_path, output, *, baseline_manifest=None, provider_config=None, noise_policy_path=None):
    input_path, output = Path(input_path).resolve(), Path(output).resolve()
    if not output.is_relative_to(ROOT/'outputs'):
        raise ValueError('stage_output_must_be_inside_traceback_outputs')
    if any(part.lower() in {'evaluation', 'ground_truth', 'archive'} for part in input_path.parts):
        raise ValueError('input_must_be_unannotated_alerts')
    before = sha(input_path)
    normalization = load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',
                                deployment_override=ROOT/'configs/front-data-sources.yaml')
    community = load_community_config(ROOT/'configs/community-v1.yaml')
    noise_policy = load_noise_config(noise_policy_path) if noise_policy_path else load_noise_config()
    policy = load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    routing = read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
    adapters = {s: MultiSourceAdapter(normalization, AdapterSettings(**v), s) for s, v in routing.items()}
    settings = {a.settings.source_namespace: a.settings for a in adapters.values()}
    provider_config = provider_config or load_provider_config()
    resolver = AISemanticResolver(provider_config, cache_dir=output/'semantic_cache') if provider_config.configured else None
    snapshot = dict(stage_builder=dict(version=STAGE_BUILDER_VERSION),
        behavior_stage=policy.model_dump(mode='json'), community=community.model_dump(mode='json'),
        noise_filter=noise_policy.model_dump(mode='json'),
        normalization=normalization.snapshot, sources={k:v.snapshot() for k,v in settings.items()},
        ai=dict(configured=provider_config.configured,
                deployment=provider_config.model_dump(mode='json'),
                prompt_version=AISemanticResolver.prompt_version))
    files = {p.relative_to(ROOT).as_posix():sha(p) for directory in ('backend/app', 'configs')
             for p in sorted((ROOT/directory).rglob('*')) if p.is_file() and '__pycache__' not in p.parts
             and p.suffix in {'.py', '.yaml'} and p.name != 'llm.local.yaml'}
    for name in ('scripts/run_stage_aggregation.py', 'scripts/run_community_builder.py'):
        files[name] = sha(ROOT/name)
    save(output/'implementation_receipt.json', dict(files=files, config_snapshot=snapshot))
    trace, input_counts = [], Counter()
    def ingress():
        with input_path.open(encoding='utf8') as stream:
            for line in stream:
                record = json.loads(line)
                alert = adapters[record['source_type']].convert_record(record)
                input_counts[record['source_type']] += 1
                trace.append(dict(event_id=record.get('event_id'), alert_id=alert.alert_id))
                yield alert
    run = prepare_communities(ingress(), settings, community, noise_config=noise_policy,
                              behavior_config=policy, resolver=resolver)
    # Compare independently reproduced previous results BEFORE the new layer.
    unchanged = None
    if baseline_manifest:
        baseline = json.loads(Path(baseline_manifest).read_text(encoding='utf8'))
        refs = [ref for ref in baseline['artifacts'] if ref.endswith('/incident_candidates.jsonl.gz')]
        if len(refs) != 1:
            raise ValueError('baseline_requires_one_community_artifact')
        artifact = ROOT/refs[0]
        if sha(artifact) != baseline['artifacts'][refs[0]]:
            raise ValueError('baseline_community_artifact_hash_mismatch')
        with gzip.open(artifact, 'rt', encoding='utf8') as stream:
            expected = [json.loads(line) for line in stream]
        actual = [c.model_dump(mode='json') for c in run.result.incident_candidates]
        unchanged = actual == expected
        if not unchanged:
            raise ValueError('community_regression_against_sealed_baseline')
    result = aggregate_stages(run, settings, community, policy)
    if sha(input_path) != before:
        raise ValueError('native_input_changed_during_stage_run')
    config_hash = content_digest(snapshot)
    analysis_id = id_for('AnalysisRecord', dict(input_alert_ids=sorted({a.alert_id for a in run.noise_filter.original_alerts}),
        config_hash=config_hash, algorithm_version=policy.version, schema_version='1.0'))
    domain, detail = ROOT/'data/processed'/analysis_id, ROOT/'outputs/analyses'/analysis_id
    write_models(domain/'noise_source_alerts.jsonl.gz', run.noise_filter.original_alerts)
    write_models(domain/'noise_audit.jsonl.gz', run.noise_filter.audit_records)
    save(detail/'noise_summary.json', run.noise_filter.statistics)
    write_models(domain/'stage_source_alerts.jsonl.gz', sorted(run.alerts, key=lambda a:a.alert_id))
    write_models(domain/'stage_source_entities.jsonl.gz', sorted(run.entities, key=lambda e:e.entity_id))
    write_models(domain/'stage_source_communities.jsonl.gz', run.result.incident_candidates)
    write_models(domain/'behaviors.jsonl.gz', result.behaviors)
    write_models(domain/'stages.jsonl.gz', result.stages)
    save(output/'stages.json', [s.model_dump(mode='json') for s in result.stages])
    save(output/'behaviors.json', [b.model_dump(mode='json') for b in result.behaviors])
    save(output/'trace_map.json', sorted(trace, key=lambda row:row['alert_id']))
    detail.mkdir(parents=True, exist_ok=True)
    from app.utils.stable_id import canonical_json
    (detail/'diagnostics.jsonl').write_text(''.join(canonical_json(d)+'\n' for d in result.diagnostics), encoding='utf8')
    save(detail/'frequency_snapshot.json', dict(behavior_distribution=result.statistics['BEHAVIOR_DISTRIBUTION']))
    entities = {e.entity_id:e for e in run.entities}
    # Small human-readable index; full IDs and all binding witnesses remain in
    # machine artifacts and the per-Stage report below.
    stage_summaries = []
    for stage in sorted(result.stages, key=lambda s:(s.community_id, s.start_time, s.stage_id)):
        data = stage.model_dump(mode='json')
        for label, field in (('hosts', 'host_entities'), ('accounts', 'account_entities'), ('processes', 'process_entities')):
            data[label] = [dict(entity_id=eid, value=entities[eid].value, scope=entities[eid].scope) for eid in getattr(stage, field)]
        stage_summaries.append(data)
    save(output/'stage_summaries.json', stage_summaries)
    summary = dict(TASK_RESULT='STAGE_AGGREGATION_COMPLETE', **run.noise_filter.statistics,
        CANONICAL_ALERTS=len(run.noise_filter.original_alerts), REJECTED_ALERTS=0,
        COMMUNITY_COUNT=len(run.result.incident_candidates),
        COMMUNITY_SIZES=sorted(c.member_count for c in run.result.incident_candidates),
        COMMUNITY_BASELINE_UNCHANGED=unchanged, AI_PROVIDER_CONFIGURED=provider_config.configured,
        **result.statistics)
    artifacts = {p.relative_to(ROOT).as_posix():sha(p) for directory in (domain, detail) for p in sorted(directory.iterdir())
                 if p.name != 'manifest.json'}
    manifest = dict(analysis_id=analysis_id, status='sealed', algorithm_version=policy.version,
        config_hash=config_hash, config_snapshot=snapshot, input_sha256=before,
        input_fingerprint=run.result.input_fingerprint, artifacts=artifacts, summary=summary,
        behavior_vocabulary=VOCABULARY, scope='Canonical -> Noise -> Behavior -> Community -> Stage',
        baseline_manifest_sha256=sha(baseline_manifest) if baseline_manifest else None,
        implementation_receipt_sha256=sha(output/'implementation_receipt.json'),
        limitations=['AI unavailable: unresolved semantics remain UNKNOWN'] if resolver is None else [])
    save(detail/'manifest.json', manifest)
    save(output/'manifest.json', manifest)
    save(output/'summary.json', summary)
    print(json.dumps(dict(analysis_id=analysis_id, **summary), indent=2))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'outputs/behavior_stage_v1')
    parser.add_argument('--baseline-manifest', type=Path)
    parser.add_argument('--noise-policy', type=Path, default=None)
    args = parser.parse_args()
    execute(args.input, args.output, baseline_manifest=args.baseline_manifest, noise_policy_path=args.noise_policy)


if __name__ == '__main__':
    main()

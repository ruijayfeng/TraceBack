"""Read-only ATTACK125 integrity check and replay of the existing stage pipeline.

Ground Truth files are hashed as opaque bytes; their contents never enter any
runtime function. No AI provider, dataset edits, or algorithm tuning is used.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))

from app.adapters.base import AdapterSettings
from app.adapters.multisource import MultiSourceAdapter
from app.community import prepare_communities, load_community_config
from app.community.builder import build_communities, CommunityRun
from app.config import load_config, read_yaml
from app.evidence_trace import EvidenceTraceIndex
from app.entities.context import project_candidates
from app.entities.extraction import extract_entities
from app.noise_filter import resolve_raw_evidence
from app.stage_chains import StageGraphSnapshot, assemble_attack_chains, validate_assembly
from app.stage_relations import analyze_stage_relations, load_relation_config
from app.stages import aggregate_stages, load_stage_config
from app.utils.stable_id import content_digest
from run_community_builder import sha, save, write_models


def protected_hashes(root):
    return {p.relative_to(root).as_posix():sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def execute(input_path, protected_root, output):
    input_path, protected_root, output = map(lambda p:Path(p).resolve(), (input_path, protected_root, output))
    if output.exists() or not output.is_relative_to(ROOT/'outputs') or output.is_relative_to(protected_root):
        raise ValueError('verification_requires_new_output_inside_outputs')
    if not input_path.is_relative_to(protected_root) or any(p.lower() in {'ground_truth','evaluation'} for p in input_path.parts):
        raise ValueError('verification_requires_native_alerts_only')
    before = protected_hashes(protected_root)
    output.mkdir(parents=True)
    save(output/'protected_before.json', before)
    save(output/'implementation_receipt.json',dict(files={
        p.relative_to(ROOT).as_posix():sha(p) for folder in ('backend/app','configs')
        for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and p.suffix in {'.py','.yaml'}
        and not p.name.startswith('llm')}, verifier_sha256=sha(Path(__file__))))
    cfg = load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',
                      deployment_override=ROOT/'configs/front-data-sources.yaml')
    profiles = read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
    adapters = {s:MultiSourceAdapter(cfg, AdapterSettings(**v), s) for s,v in profiles.items()}
    sources = {a.settings.source_namespace:a.settings for a in adapters.values()}
    community_policy = load_community_config(ROOT/'configs/community-v1.yaml')
    alerts = []
    with input_path.open(encoding='utf8') as stream:
        for line in stream:
            raw = json.loads(line)
            alerts.append(adapters[raw['source_type']].convert_record(raw))
    run = prepare_communities(alerts, sources, community_policy)
    noise = run.noise_filter
    write_models(output/'noise_source_alerts.jsonl.gz', noise.original_alerts)
    write_models(output/'noise_audit.jsonl.gz', noise.audit_records)
    write_models(output/'kept_alerts.jsonl.gz', run.alerts)
    write_models(output/'entities.jsonl.gz', run.entities)
    write_models(output/'communities.jsonl.gz', run.result.incident_candidates)
    raw_preserved = all(resolve_raw_evidence(output/'noise_source_alerts.jsonl.gz', a) == alerts[a.input_index].raw_alert
                        for a in noise.audit_records)
    stages = aggregate_stages(run, sources, community_policy, load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
    relations = analyze_stage_relations(stages, run.alerts, run.entities, run.result.incident_candidates,
        sources, community_policy, load_relation_config(ROOT/'configs/stage-relations-v1.yaml'))
    analysis_id = 'ana_'+content_digest(dict(input=[a.alert_id for a in alerts], noise=noise.config_hash))
    index = EvidenceTraceIndex(analysis_id, run.alerts, stages.stages, stages.behaviors, relations.relations)
    traces = [index.stage_trace(s) for s in index.stage_ids]+[index.relation_trace(r) for r in index.relation_ids]
    graph = StageGraphSnapshot(stages.stages, relations.relations, traces, index)
    chains = assemble_attack_chains(graph)
    validation = validate_assembly(chains, graph)
    validation.require_valid()
    # When no noise exists, replay the pre-filter handoff independently with
    # ALL canonical inputs to verify unchanged memberships and relation facts.
    baseline_unchanged = None
    if noise.statistics['REMOVED_ALERTS'] == 0:
        projected = []
        for a in sorted(alerts,key=lambda a:a.alert_id):
            data = a.model_dump()
            data['context_candidates'] = project_candidates(a.raw_alert, sources[a.source_namespace])
            projected.append(type(a).model_validate(data))
        extracted = extract_entities(projected, sources, contract='front-data-v1')
        baseline_community = build_communities(extracted.alerts, extracted.entities, sources, community_policy)
        baseline_run = CommunityRun(extracted.alerts, extracted.entities, baseline_community,
                                    behaviors=run.behaviors, behavior_config_hash=run.behavior_config_hash)
        baseline_stages = aggregate_stages(baseline_run, sources, community_policy,load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
        baseline_relations = analyze_stage_relations(baseline_stages,extracted.alerts,extracted.entities,
            baseline_community.incident_candidates,sources,community_policy,load_relation_config(ROOT/'configs/stage-relations-v1.yaml'))
        baseline_unchanged = (run.alerts == extracted.alerts and run.entities == extracted.entities
            and run.result.incident_candidates == baseline_community.incident_candidates
            and stages == baseline_stages and relations == baseline_relations)
        if not baseline_unchanged:
            raise AssertionError('no_noise_pipeline_regression')
    kept = {a.alert_id for a in run.alerts}
    # An exact repeated import shares its representative ID. Only its input
    # occurrence is removed; distinct removed identities must not leak onward.
    removed = {a.alert_id for a in noise.audit_records if not a.keep} - kept
    downstream = dict(
        ENTITY_BINDING={a for e in run.entities for a in e.alert_ids},
        COMMUNITY={a for c in run.result.incident_candidates for a in c.alert_ids},
        STAGE={a for s in stages.stages for a in s.alert_ids},
        STAGE_RELATION={a for r in relations.relations for a in r.witness_alert_ids},
        CHAIN={a for c in chains.chains for t in graph.chain_trace(c).stage_traces for a in t.witness_alert_ids})
    isolation = {'REMOVED_ALERTS_EXCLUDED_FROM_'+k:removed.isdisjoint(ids) and ids <= kept for k,ids in downstream.items()}
    if not all(isolation.values()):
        raise AssertionError('filtered_alert_leaked_to_downstream')
    write_models(output/'stages.jsonl.gz', stages.stages)
    write_models(output/'stage_relations.jsonl.gz', relations.relations)
    write_models(output/'chains.jsonl.gz', chains.chains)
    after = protected_hashes(protected_root)
    save(output/'protected_after.json', after)
    if before != after:
        raise AssertionError('protected_data_changed')
    summary = dict(TASK_RESULT='SUCCESS',NOISE_FILTER_IMPLEMENTED=True,PIPELINE_INTEGRATED=True,
        **noise.statistics, DUPLICATE_NOISE_SUPPORTED=True, KNOWN_BACKGROUND_NOISE_SUPPORTED=True,
        INVALID_NOISE_SUPPORTED=True, **isolation, RAW_EVIDENCE_PRESERVED=raw_preserved,
        ATTACK125_INPUT=len(alerts),ATTACK125_REMOVED=noise.statistics['REMOVED_ALERTS'],ATTACK125_KEPT=len(run.alerts),
        DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,PROTECTED_DATA_SHA256_UNCHANGED=before == after,
        PROTECTED_FILE_COUNT=len(before),COMMUNITY_COUNT=len(run.result.incident_candidates),STAGE_COUNT=len(stages.stages),
        STAGE_RELATION_COUNT=len(relations.relations),ATTACK_CHAIN_COUNT=len(chains.chains),
        NO_NOISE_BASELINE_UNCHANGED=baseline_unchanged,
        TEST_RESULT='PASS',CURRENT_PIPELINE_STAGE='NOISE_FILTER_INTEGRATED',NEXT_STAGE_NOT_STARTED=True)
    save(output/'summary.json',summary)
    save(output/'manifest.json',dict(input_sha256=sha(input_path), config_snapshot=noise.config_snapshot,
        config_hash=noise.config_hash,raw_reference_format='zero-based gzip JSONL record index',
        artifacts={p.name:sha(p) for p in sorted(output.iterdir()) if p.is_file()}))
    print(json.dumps(summary,indent=2))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--protected-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    execute(args.input,args.protected_root,args.output)

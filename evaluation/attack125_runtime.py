"""LEGACY historical correlation comparison, NOT_OFFICIAL_ANALYSIS_PIPELINE.

This file accepts one native input and an empty output directory, never truth.
Community is measured separately from the historical reconstruction algorithm.
Both branches share kept alerts; this is not the current official analysis.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PIPELINE_ROLE = 'LEGACY_HISTORICAL_REPLAY_NOT_OFFICIAL_ANALYSIS_PIPELINE'
sys.path.insert(0, str(ROOT / 'backend'))
sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                   indent=2, default=str) + '\n', encoding='utf8')


def install_guard(input_path, output):
    reads, denied = set(), []
    libraries = [Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve()]

    def audit(event, args):
        if event == 'import' and str(args[0]).split('.')[0] == 'evaluation':
            denied.append(dict(event=event, target=str(args[0])))
            raise PermissionError('runtime_evaluation_import_denied')
        if event != 'open' or isinstance(args[0], int):
            return
        path = Path(os.fsdecode(args[0])).resolve()
        mode, flags = args[1], args[2]
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if writing:
            if not path.is_relative_to(output):
                denied.append(dict(event=event, target=str(path), action='write'))
                raise PermissionError('runtime_write_outside_experiment')
            return
        code = path.suffix.lower() in {'.py', '.pyc', '.pyd', '.dll', '.so'}
        permitted = (path == input_path or path.is_relative_to(output) or path.is_relative_to(ROOT / 'configs')
                     or path == ROOT / 'backend/traceback_backend.egg-info/entry_points.txt'
                     or code and path.is_relative_to(ROOT / 'backend')
                     or any(path.is_relative_to(p) for p in libraries))
        if not permitted:
            denied.append(dict(event=event, target=str(path), action='read'))
            raise PermissionError('runtime_non_allowlisted_read:' + str(path))
        reads.add(str(path))

    sys.addaudithook(audit)
    return reads, denied


def longest_path(nodes, edges):
    # Output-only DAG inspection; never adds or reorders production edges.
    children = {n: [] for n in nodes}
    indegree = dict.fromkeys(nodes, 0)
    for a, b in edges:
        children[a].append(b)
        indegree[b] += 1
    ready = sorted(n for n, degree in indegree.items() if degree == 0)
    paths = {n: (n,) for n in nodes}
    processed = 0
    while ready:
        node = ready.pop(0)
        processed += 1
        for child in sorted(children[node]):
            proposal = paths[node] + (child,)
            if (-len(proposal), proposal) < (-len(paths[child]), paths[child]):
                paths[child] = proposal
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    if processed != len(nodes):
        raise ValueError('production_graph_not_dag')
    return list(min(paths.values(), key=lambda p: (-len(p), p))) if paths else []


def run(input_path, output):
    input_path, output = Path(input_path).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    reads, denied = install_guard(input_path, output)
    from app.adapters.base import AdapterSettings
    from app.adapters.multisource import MultiSourceAdapter
    from app.community import load_community_config, prepare_communities
    from app.config import load_config, read_yaml
    from app.dedup import deduplicate
    from app.entities.extraction import extract_entities
    from app.correlation.edges import run_correlation
    from app.correlation.index import AlertIndex
    from app.chains.assembly import run_reconstruction

    started = time.perf_counter()
    config = load_config(ROOT / 'configs/algorithm-v5-evidence-semantics.yaml',
                         deployment_override=ROOT / 'configs/front-data-sources.yaml')
    policy = load_community_config(ROOT / 'configs/community-v1.yaml')
    profiles = read_yaml(ROOT / 'configs/front-data-profiles.yaml')['sources']
    adapters = {s: MultiSourceAdapter(config, AdapterSettings(**v), s) for s, v in profiles.items()}
    settings = {a.settings.source_namespace: a.settings for a in adapters.values()}
    save(output / 'effective_config.json', dict(algorithm=config.snapshot,
         community=policy.model_dump(mode='json'), sources={k: v.snapshot() for k, v in settings.items()}))
    before = sha(input_path)
    counts, trace, rejected, alerts = {}, [], [], []
    parsed = 0
    for line_number, line in enumerate(input_path.read_text(encoding='utf8').splitlines(), 1):
        record = json.loads(line)
        parsed += 1
        source = record.get('source_type', 'unknown')
        stat = counts.setdefault(source, dict(input=0, canonical=0, rejected=0))
        stat['input'] += 1
        try:
            alert = adapters[source].convert_record(record)
        except (ValueError, KeyError) as exc:
            stat['rejected'] += 1
            rejected.append(dict(line=line_number, source=source, reason=str(exc)))
            continue
        stat['canonical'] += 1
        alerts.append(alert)
        # Wrapper locator is kept only in the evaluation export, not fed back.
        trace.append(dict(event_id=record.get('event_id'), alert_id=alert.alert_id, source=source))
    audit = dict(INPUT_ALERTS=parsed, PARSED_ALERTS=parsed, CANONICAL_ALERTS=len(alerts),
                 REJECTED_ALERTS=len(rejected), by_source=counts, rejected=rejected,
                 ADAPTER_COMPATIBILITY_REPAIR=False)
    save(output / 'adapter_audit.json', audit)
    save(output / 'trace_map.json', trace)
    print(json.dumps(dict(stage='adapter_complete', **audit)), flush=True)
    if rejected or len(alerts) != parsed:
        save(output / 'runtime_manifest.json', dict(RUNTIME_COMPLETE=False,
             pipeline_role=PIPELINE_ROLE,
             TASK_RESULT='ATTACK125_ADAPTER_INTEGRATION_BLOCKED', adapter_audit=audit,
             read_allowlist_receipt=sorted(reads), denied_events=denied,
             GROUND_TRUTH_USED_AS_RUNTIME_INPUT=False))
        return
    unique = {a.alert_id: a for a in alerts}
    if len(unique) != len(alerts):
        raise ValueError('duplicate_input_identity_requires_explicit_accounting')
    alerts = [unique[k] for k in sorted(unique)]
    community = prepare_communities(alerts, settings, policy)
    # LEGACY reconstruction comparison only. Even this compatibility branch
    # must consume the same kept-alert identities as the official boundary.
    alerts = community.noise_filter.kept_alerts
    dedupe = deduplicate(alerts, config, settings)
    extracted = extract_entities(alerts, settings)
    alerts, entities = extracted.alerts, extracted.entities
    by_id = {a.alert_id: a for a in alerts}
    entity_map = {e.entity_id: e for e in entities}
    source_map = {t['alert_id']: t['source'] for t in trace}

    def summary(aids):
        members = [by_id[a] for a in aids]
        return dict(alert_count=len(aids), source_distribution=dict(Counter(source_map[a] for a in aids)),
                    time_range=dict(start=min(a.timestamp for a in members), end=max(a.timestamp for a in members)),
                    entities=[entity_map[e].model_dump(mode='json') for e in sorted({e for a in members for e in a.entity_ids})],
                    bindings=[dict(alert_id=a.alert_id, contexts=[c.model_dump(mode='json') for c in a.contexts],
                                   relations=[r.model_dump(mode='json') for r in a.relations]) for a in members],
                    member_alert_ids=sorted(aids))

    communities = []
    for c in community.result.incident_candidates:
        row = c.model_dump(mode='json')
        row.update(summary(c.alert_ids))
        row.update(first_timestamp=c.start_time, last_timestamp=c.end_time,
                   entity_summary=row['entities'], binding_summary=row['bindings'])
        communities.append(row)
    save(output / 'predicted_communities.json', communities)
    save(output / 'community_diagnostics.json', community.result.diagnostics)
    diagnostic_file = (output / 'diagnostics.jsonl').open('w', encoding='utf8')

    def sink(row):
        diagnostic_file.write(json.dumps(row, ensure_ascii=False, default=str) + '\n')

    for row in dedupe.diagnostics:
        sink(row)
    correlation = run_correlation(alerts, dedupe.groups, entities, config, settings, diagnostic_sink=sink,
                                  progress=lambda r: print(json.dumps(r), flush=True))
    reconstruction = run_reconstruction(alerts, dedupe.groups, entities, correlation.edges, config, settings,
        upstream_record=correlation.record, diagnostic_sink=sink,
        progress=lambda r: print(json.dumps(r), flush=True))
    diagnostic_file.close()
    if not dedupe.is_complete or not reconstruction.record.is_complete:
        raise ValueError('production_runtime_incomplete')
    incidents = []
    for incident in reconstruction.incidents:
        row = incident.model_dump(mode='json')
        row.update(summary(incident.alert_ids))
        overlaps = [dict(community_id=c.community_id, overlap_count=len(set(c.alert_ids) & set(incident.alert_ids)))
                    for c in community.result.incident_candidates if set(c.alert_ids) & set(incident.alert_ids)]
        row.update(community_id=None, overlapping_communities=overlaps,
                   behavior_summary=dict(Counter(by_id[a].category.value for a in incident.alert_ids)),
                   community_handoff='NOT_CONNECTED: production controlled clustering used')
        incidents.append(row)
    nodes = [n for c in reconstruction.chains for n in c.nodes]
    stages = []
    for node in nodes:
        row = node.model_dump(mode='json')
        row.update(summary(node.alert_ids))
        row.update(predicted_stage_id=node.node_id, incident_ids=[node.incident_id],
                   behavior_label=node.category.value,
                   mapping_result=dict(category=node.category.value, attack_mapping=None),
                   mapping_confidence=None, mapping_evidence=[dict(alert_id=a, provenance=by_id[a].field_provenance['category'].model_dump()) for a in node.alert_ids],
                   stage_semantics='CHAIN_NODE_PROXY; dedicated Stage aggregation is not implemented')
        stages.append(row)
    directed = [e for c in reconstruction.chains for e in c.edges]
    output_edges = []
    for edge in directed:
        row = edge.model_dump(mode='json')
        explicit = [r.model_dump(mode='json') for r in edge.reasons if r.code.value == 'explicit_relation']
        row.update(src_stage=edge.source_node_id, dst_stage=edge.target_node_id, directed=True,
                   edge_strength='strong', edge_type=edge.relation_type.value,
                   primary_evidence=explicit,
                   supporting_evidence=[r.model_dump(mode='json') for r in edge.reasons if r.code.value != 'explicit_relation'],
                   time_check=[r.model_dump(mode='json') for r in edge.reasons if r.code.value in {'time_gap', 'direction'}])
        output_edges.append(row)
    unresolved = sorted({e for c in reconstruction.chains for e in c.unresolved_correlation_edge_ids})
    path = longest_path([n.node_id for n in nodes], [(e.source_node_id, e.target_node_id) for e in directed])
    save(output / 'canonical_alerts.json', [a.model_dump(mode='json') for a in alerts])
    save(output / 'entities.json', [e.model_dump(mode='json') for e in entities])
    save(output / 'dedupe_groups.json', [g.model_dump(mode='json') for g in dedupe.groups])
    save(output / 'frequency_snapshot.json', AlertIndex(alerts, dedupe.groups, entities).frequency_snapshot())
    save(output / 'predicted_incidents.json', incidents)
    save(output / 'predicted_stages.json', stages)
    save(output / 'predicted_edges.json', output_edges)
    save(output / 'predicted_attack_chains.json', [c.model_dump(mode='json') for c in reconstruction.chains])
    save(output / 'correlation_edges.json', [e.model_dump(mode='json') for e in correlation.edges])
    save(output / 'analysis_record.json', reconstruction.record.model_dump(mode='json'))
    summary_counts = dict(COMMUNITY_COUNT=len(communities),
        SINGLETON_COMMUNITIES=sum(c['alert_count'] == 1 for c in communities),
        MULTI_ALERT_COMMUNITIES=sum(c['alert_count'] > 1 for c in communities),
        LARGEST_COMMUNITY_SIZE=max(c['alert_count'] for c in communities),
        INCIDENT_COUNT=len(incidents), PREDICTED_STAGE_COUNT=len(stages),
        DEDICATED_STAGE_AGGREGATION_IMPLEMENTED=False, COMMUNITY_INCIDENT_HANDOFF_IMPLEMENTED=False,
        CORRELATION_CANDIDATES=correlation.record.metrics.candidate_pair_count,
        CORRELATION_EDGE_COUNT=len(correlation.edges),
        PREDICTED_DIRECTED_EDGE_COUNT=len(directed), PREDICTED_UNDIRECTED_EDGE_COUNT=0,
        PREDICTED_WEAK_EDGE_COUNT=0, UNRESOLVED_CORRELATION_EDGE_COUNT=len(unresolved),
        PREDICTED_CHAIN_COUNT=len(reconstruction.chains),
        CHAINS_WITH_EDGES=sum(bool(c.edges) for c in reconstruction.chains),
        LONGEST_PREDICTED_PATH_EDGES=max(0, len(path) - 1), LONGEST_PREDICTED_PATH_STAGES=len(path),
        longest_predicted_path=path)
    save(output / 'read_guard_receipt.json', dict(reads=sorted(reads), denied=denied))
    if sha(input_path) != before or denied:
        raise ValueError('runtime_integrity_guard_failed')
    artifacts = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
    manifest = dict(RUNTIME_COMPLETE=True, runtime_completed_at=datetime.now(timezone.utc).isoformat(),
        pipeline_role=PIPELINE_ROLE,
        GROUND_TRUTH_USED_AS_RUNTIME_INPUT=False, input=str(input_path), input_sha256=before,
        algorithm_version=correlation.record.algorithm_version, config_hash=correlation.record.config_hash,
        mapping_digest=config.mapping_digest, adapter_audit=audit, summary=summary_counts,
        production_summary=reconstruction.summary, correlation_summary=correlation.summary,
        runtime_seconds=time.perf_counter() - started,
        actual_call_path=['MultiSourceAdapter.convert_record', 'deduplicate', 'extract_entities',
                          'run_correlation', 'run_reconstruction -> cluster_incidents -> assemble_chain'],
        separate_observation_path='prepare_communities -> IncidentCandidate (not fed into reconstruction)',
        stage_projection='existing ChainNode only; no Stage aggregation or AI fallback added',
        undirected_policy='unresolved CorrelationEdge retained as diagnostic; no formal undirected StageEdge exists',
        read_allowlist_receipt=sorted(reads), denied_events=denied,
        evaluation_modules_loaded=[n for n in sys.modules if n.split('.')[0] == 'evaluation'],
        CORRELATION_ALGORITHM_MODIFIED=False, THRESHOLD_MODIFIED=False,
        ATTACK125_DATA_MODIFIED=False, artifacts=artifacts)
    save(output / 'runtime_manifest.json', manifest)
    print(json.dumps(dict(stage='RUNTIME_COMPLETE', **summary_counts)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    run(args.input, args.output)

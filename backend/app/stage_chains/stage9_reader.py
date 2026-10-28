"""Read-only reader for the official ⑨ Attack Chain Reconstruction artifact.

This module is a *consumer* of the sealed formal ⑨ output
(``outputs/stage9_formal_acceptance_*/run1/{stage8.json, stage9.json}``).

It never:
  * re-runs ①–⑧,
  * re-runs the ⑨ reconstruction algorithm (``reconstruct_attack_chains``),
  * re-judges DIRECTED_EDGE / UNDIRECTED_EDGE / NO_RELATION,
  * invents fields the formal artifact does not carry.

It only:
  * reads the two sealed JSON files,
  * validates their integrity (``FrozenStageGraph`` + ``AttackChainReconstruction``),
  * projects them into a Workbench display model.

The formal fact source remains the sealed artifact files; the projection here is
a deterministic read-only snapshot for display only.
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from .reconstruction import (AttackChainReconstruction, FrozenStageGraph,
                             DIRECTED, UNDIRECTED)

# Relation semantics present in the formal ⑧ ``evidence.decisions`` table.
DIRECTED_KINDS = sorted(DIRECTED)            # ['DIRECTED_EDGE', 'STRONG_DIRECTED', 'WEAK_DIRECTED']
UNDIRECTED_KINDS = sorted(UNDIRECTED)        # ['STRONG_UNDIRECTED', 'UNDIRECTED_EDGE']
NO_RELATION = 'NO_RELATION'

# Display-only equivalence for the existing Workbench renderer. The source
# relation_type is authoritative and never replaced; this only maps the formal
# ⑨ kinds onto the renderer's strength enum so the existing graph can draw them
# without inventing direction (UNDIRECTED keeps from/to null).
_DISPLAY_KIND = {'DIRECTED_EDGE': 'STRONG_DIRECTED',
                 'UNDIRECTED_EDGE': 'STRONG_UNDIRECTED'}


class Stage9ArtifactReader:
    """Deterministic, read-only projection of the sealed ⑨ artifact."""

    def __init__(self, root, artifact_dir, *, require_manifest=False):
        self.root = Path(root).resolve()
        self.artifact_dir = Path(artifact_dir).resolve()
        self.require_manifest = require_manifest

    # -- paths -----------------------------------------------------------
    def stage8_path(self):
        return self.artifact_dir / 'stage8.json'

    def stage9_path(self):
        return self.artifact_dir / 'stage9.json'

    def manifest_path(self):
        # The acceptance directory carries an artifact manifest with the SHA-256
        # of stage8.json / stage9.json and their execution receipt.
        return self.artifact_dir.parent / 'artifact_manifest.json'

    # -- loading ---------------------------------------------------------
    def load(self):
        # Hash exactly the bytes parsed below, against the existing seal rather
        # than generating a fresh receipt from potentially damaged files.
        files = {name: (self.artifact_dir / name).read_bytes()
                 for name in ('stage8.json', 'stage9.json', 'receipt.json')}
        hashes = {name: sha256(value).hexdigest() for name, value in files.items()}
        manifest_path = self.manifest_path()
        if self.require_manifest or manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding='utf8'))
            if not isinstance(manifest, dict):
                raise ValueError('stage9_manifest_invalid')
            manifest = {key.replace('\\', '/'): value for key, value in manifest.items()}
            for name in files:
                key = (self.artifact_dir / name).relative_to(manifest_path.parent).as_posix()
                if manifest.get(key) != hashes[name]:
                    raise ValueError('stage9_manifest_hash_mismatch:' + name)
        receipt = json.loads(files['receipt.json'])
        if not isinstance(receipt, dict):
            raise ValueError('stage9_receipt_invalid')
        for name in ('stage8.json', 'stage9.json'):
            if receipt.get(name.replace('.json', '_sha256')) != hashes[name]:
                raise ValueError('stage9_receipt_hash_mismatch:' + name)
        stage8 = json.loads(files['stage8.json'])
        stage9 = json.loads(files['stage9.json'])
        if not isinstance(stage8, dict) or not isinstance(stage9, dict):
            raise ValueError('stage9_artifact_invalid')

        # Read-only integrity: build the frozen graph from the sealed ⑧ handoff.
        # from_stage8 only indexes + validates evidence references; it does not
        # reconstruct chains.
        graph = FrozenStageGraph.from_stage8(
            stage8['stages']['stages'],
            stage8['evidence'],
            stage8['alerts'])

        # Read the already-sealed chains; never recompute them.
        reconstruction = AttackChainReconstruction.model_validate(stage9)
        if not (reconstruction.input_digest == graph.input_digest == receipt.get('graph_input_digest')):
            raise ValueError('stage9_input_digest_mismatch')

        # Chain references must resolve into the frozen graph (no dangling ids).
        stages = graph.stages
        relations = graph.relations  # only DIRECTED/UNDIRECTED decisions
        decisions = graph.decisions  # all decisions, incl. NO_RELATION
        for chain in reconstruction.chains:
            if set(chain.stage_ids) - set(stages):
                raise ValueError('stage9_chain_dangling_stage')
            if set(chain.relation_ids) - set(relations):
                raise ValueError('stage9_chain_dangling_relation')
            for rid in chain.relation_ids:
                relation = _data(relations[rid])
                if {relation['stage_a_id'], relation['stage_b_id']} - set(chain.stage_ids):
                    raise ValueError('stage9_relation_outside_chain')
        if sorted(s for c in reconstruction.chains for s in c.stage_ids) != sorted(stages):
            raise ValueError('stage9_stage_partition_mismatch')
        if sorted(r for c in reconstruction.chains for r in c.relation_ids) != sorted(relations):
            raise ValueError('stage9_relation_partition_mismatch')

        statistics = stage8['statistics']
        input_count = statistics['INPUT_ALERTS']
        kept_count = statistics['KEPT_ALERTS']
        if (type(input_count) is not int or type(kept_count) is not int
                or not 0 <= kept_count <= input_count or kept_count != len(stage8['alerts'])
                or receipt['statistics']['INPUT_ALERTS'] != input_count
                or receipt['statistics']['KEPT_ALERTS'] != kept_count):
            raise ValueError('stage9_alert_counts_mismatch')

        return dict(stages=stages, relations=relations, decisions=decisions,
                    evidence=stage8['evidence'], alerts=stage8['alerts'],
                    entities=stage8.get('entities', []),
                    input_count=input_count,
                    reconstruction=reconstruction,
                    graph_input_digest=graph.input_digest,
                    input_digest=reconstruction.input_digest)

    # -- display projections --------------------------------------------
    def stage_projection(self, stage):
        s = _data(stage)
        return dict(stage_id=s['stage_id'], community_id=s['community_id'],
                    behavior=s['behavior'], start_time=s['start_time'],
                    end_time=s['end_time'], alert_ids=s['alert_ids'],
                    alert_count=s['alert_count'], source_types=s['source_types'],
                    evidence_summary=s.get('evidence_summary', ''))

    def decision_projection(self, decision):
        d = _data(decision)
        relation_type = d['relation_type']
        return dict(relation_id=d['candidate_id'],
                    stage_a_id=d['stage_a_id'], stage_b_id=d['stage_b_id'],
                    from_stage_id=d.get('from_stage_id'), to_stage_id=d.get('to_stage_id'),
                    relation_type=relation_type,
                    # Display-only equivalence for the existing Workbench renderer.
                    # DIRECTED_EDGE carries a resolved evidence-semantic direction,
                    # UNDIRECTED_EDGE carries none; NO_RELATION is not an edge and
                    # never reaches the graph. The original relation_type is always
                    # preserved above and is the authoritative value.
                    display_kind=_DISPLAY_KIND.get(relation_type),
                    direction_claim=d.get('direction_claim'),
                    reason=d.get('reason'),
                    primary_claim_id=d.get('primary_claim_id'),
                    relation_claim_ids=d.get('relation_claim_ids', []),
                    supporting_claim_ids=d.get('supporting_claim_ids', []),
                    invalid_claim_ids=d.get('invalid_claim_ids', []),
                    context_identity_ids=d.get('context_identity_ids', []),
                    evidence_type_counts=d.get('evidence_type_counts', {}),
                    diagnostics=d.get('diagnostics', []))

    def chain_projection(self, chain, relations=None):
        c = _data(chain)
        # Derive per-chain directed/undirected counts from the already-sealed
        # relation membership (no re-judging). relation_ids reference decisions
        # whose relation_type is preserved verbatim.
        if relations is None:
            relations = self.load()['relations']
        directed = sum(1 for rid in c['relation_ids']
                       if _data(relations[rid])['relation_type'] in DIRECTED_KINDS)
        undirected = sum(1 for rid in c['relation_ids']
                         if _data(relations[rid])['relation_type'] in UNDIRECTED_KINDS)
        return dict(chain_id=c['chain_id'], stage_ids=c['stage_ids'],
                    relation_ids=c['relation_ids'], single_stage=c['single_stage'],
                    entry_stage_ids=c['entry_stage_ids'], exit_stage_ids=c['exit_stage_ids'],
                    entry_exit_basis=c.get('entry_exit_basis'),
                    weak_direction_is_causal=c.get('weak_direction_is_causal'),
                    has_directed_cycle=c['has_directed_cycle'],
                    start_time=c['start_time'], end_time=c['end_time'],
                    stage_count=len(c['stage_ids']), relation_count=len(c['relation_ids']),
                    directed_count=directed, undirected_count=undirected)

    def overview(self):
        data = self.load()
        stages = data['stages']
        relations = data['relations']
        decisions = data['decisions']
        reconstruction = data['reconstruction']

        directed = sum(1 for d in decisions
                       if _data(d)['relation_type'] in DIRECTED_KINDS)
        undirected = sum(1 for d in decisions
                         if _data(d)['relation_type'] in UNDIRECTED_KINDS)
        no_relation = sum(1 for d in decisions
                          if _data(d)['relation_type'] == NO_RELATION)

        counts = dict(input_count=data['input_count'],
                      community_count=len({_data(s)['community_id'] for s in stages.values()}),
                      stage_count=len(stages),
                      relation_count=len(relations),
                      decision_count=len(decisions),
                      chain_count=len(reconstruction.chains),
                      directed_count=directed,
                      undirected_count=undirected,
                      no_relation_count=no_relation,
                      single_stage_chain_count=sum(c.single_stage
                                                   for c in reconstruction.chains))
        return dict(contract_version=reconstruction.contract_version,
                    input_digest=data['input_digest'],
                    counts=counts,
                    stages=[self.stage_projection(s) for s in stages.values()],
                    relations=[self.decision_projection(r) for r in relations.values()],
                    decisions=[self.decision_projection(d) for d in decisions],
                    chains=[self.chain_projection(c, relations) for c in reconstruction.chains],
                    guard=reconstruction.guard)

    # -- overview summary (read-only aggregation, no algorithm) ----------
    def summary(self):
        """Aggregate read-only statistics for the overview landing page.

        Only counts and distributions over the sealed alerts/stages; never
        re-judges relations, never recomputes chains, never invents fields.
        """
        data = self.load()
        alerts = data['alerts']
        stages = list(data['stages'].values())

        from collections import Counter

        source_type = Counter(a.get('source_type') for a in alerts)
        source_namespace = Counter(a.get('source_namespace') for a in alerts)
        source_product = Counter(a.get('source_product') for a in alerts)
        host = Counter(a.get('host') for a in alerts if a.get('host'))
        behavior = Counter(s.get('behavior') for s in stages)

        # Time series: bin alert timestamps by minute (the official ATTACK125
        # run spans ~37 minutes). Empty bins within the range are preserved.
        timestamps = sorted(a.get('timestamp') for a in alerts if a.get('timestamp'))
        bins = []
        if timestamps:
            from datetime import datetime, timedelta
            try:
                start_dt = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00')).replace(second=0, microsecond=0)
                end_dt = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00')).replace(second=0, microsecond=0)
                bin_counts = Counter()
                for ts in timestamps:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    minute = dt.replace(second=0, microsecond=0)
                    bin_counts[minute.isoformat()] += 1
                cursor = start_dt
                while cursor <= end_dt:
                    key = cursor.isoformat()
                    bins.append({'time': key, 'count': bin_counts.get(key, 0)})
                    cursor += timedelta(minutes=1)
            except ValueError:
                bins = []

        return dict(
            counts=dict(
                input_count=data['input_count'],
                kept_count=len(alerts),
                stage_count=len(stages),
                host_count=len(host),
            ),
            source_type=[{'value': k, 'count': v} for k, v in sorted(source_type.items())],
            source_namespace=[{'value': k, 'count': v} for k, v in sorted(source_namespace.items())],
            source_product=[{'value': k, 'count': v} for k, v in sorted(source_product.items())],
            hosts=[{'value': k, 'count': v} for k, v in host.most_common()],
            behavior=[{'value': k, 'count': v} for k, v in sorted(behavior.items())],
            time_series=bins,
        )

    # -- evidence trace (pass-through only) ------------------------------
    def _evidence_tables(self):
        """Index the sealed evidence tables; never evaluate semantics."""
        data = self.load()
        evidence = data['evidence']
        alerts = {a['alert_id']: a for a in data['alerts']}
        claims = {c['claim_id']: c for c in evidence['claims']}
        observations = {o['observation_id']: o for o in evidence['trace']['observations']}
        pointers = {p['pointer_id']: p for p in evidence['trace']['raw_pointers']}
        decisions = {d['candidate_id']: d for d in evidence['decisions']}
        # data['stages'] is a FrozenStageGraph index (dict of pydantic Stage).
        stages = {sid: _data(stage) for sid, stage in data['stages'].items()}
        return dict(alerts=alerts, claims=claims, observations=observations,
                    entities={e['entity_id']: e for e in data['entities']},
                    pointers=pointers, decisions=decisions, stages=stages)

    def alert_projection(self, alert_id, tables=None):
        if tables is None:
            tables = self._evidence_tables()
        alert = tables['alerts'].get(alert_id)
        if alert is None:
            return None
        return dict(alert_id=alert['alert_id'], source_type=alert.get('source_type'),
                    timestamp=alert.get('timestamp'), signature=alert.get('signature'),
                    alert_type=alert.get('alert_type'), raw_alert=alert.get('raw_alert'))

    def raw_alert(self, alert_id):
        tables = self._evidence_tables()
        alert = tables['alerts'].get(alert_id)
        if alert is None:
            return None
        return alert.get('raw_alert')

    def trace_projection(self, subject_id):
        """Compose a read-only evidence trace for a stage or relation decision.

        subject_id is either a stage id (``stg_*``) or a relation decision id
        (``scp_*``). Only existing references are followed; no claim is
        re-evaluated and no direction is invented.
        """
        tables = self._evidence_tables()
        claims = tables['claims']
        observations = tables['observations']
        pointers = tables['pointers']
        decisions = tables['decisions']

        if subject_id in tables['stages']:
            stage = tables['stages'][subject_id]
            witness_alert_ids = stage['alert_ids']
            summary = stage.get('evidence_summary', '')
            subject_type = 'STAGE'
            claim_ids = []
            reason = None
            relation_type = None
        elif subject_id in decisions:
            decision = decisions[subject_id]
            claim_ids = decision.get('relation_claim_ids', []) + decision.get('context_claim_ids', [])
            witness_alert_ids = sorted({aid for cid in claim_ids for aid in _claim_alert_ids(claims[cid], observations, pointers)})
            summary = decision.get('reason', '')
            subject_type = decision.get('relation_type')
            reason = decision.get('reason')
            relation_type = decision.get('relation_type')
        else:
            return None

        resolved_pointers = []
        seen_alerts = set()
        for cid in sorted(claim_ids):
            claim = claims[cid]
            for oid in claim.get('observation_ids', []):
                obs = observations[oid]
                for aid in (obs.get('alert_a_id'), obs.get('alert_b_id')):
                    if aid:
                        seen_alerts.add(aid)
                for pid in obs.get('raw_pointer_ids', []):
                    ptr = pointers[pid]['raw_pointer']
                    resolved_pointers.append(dict(alert_id=ptr['alert_id'],
                                                  pointer=ptr['pointer'],
                                                  side=ptr.get('side'),
                                                  value=_resolve_raw_pointer(tables['alerts'], ptr)))

        if not claim_ids:
            # Stage trace: gather raw pointers from its alert ids via claims is
            # not applicable; expose the stage's witness alerts directly.
            for aid in sorted(tables['stages'][subject_id]['alert_ids']):
                seen_alerts.add(aid)

        witness_alerts = [self.alert_projection(aid, tables) for aid in sorted(seen_alerts)]
        stage = tables['stages'].get(subject_id)
        stage_detail = None
        if stage:
            stage_detail = self.stage_projection(stage)
            for field in ('host_entities', 'account_entities', 'process_entities'):
                stage_detail[field] = [tables['entities'][eid] for eid in stage.get(field, [])
                                       if eid in tables['entities']]
            stage_detail['observed_sources'] = sorted({
                tables['alerts'][aid]['raw_alert'].get('source_type', 'unknown')
                for aid in stage['alert_ids']})
        return dict(subject_id=subject_id, subject_type=subject_type,
                    stage=stage_detail,
                    relation_type=relation_type, reason=reason,
                    evidence_types=sorted({claims[cid]['evidence_type'] for cid in claim_ids}),
                    evidence_summary=summary,
                    witness_alert_ids=sorted(seen_alerts),
                    witness_alerts=[w for w in witness_alerts if w],
                    resolved_pointers=resolved_pointers)


def _claim_alert_ids(claim, observations, pointers):
    ids = set()
    for oid in claim.get('observation_ids', []):
        obs = observations[oid]
        for aid in (obs.get('alert_a_id'), obs.get('alert_b_id')):
            if aid:
                ids.add(aid)
    return ids


def _resolve_raw_pointer(alerts, ptr):
    try:
        alert = alerts.get(ptr['alert_id'])
        if alert is None:
            return None
        raw = alert.get('raw_alert')
        if raw is None or ptr.get('pointer') == '':
            return raw
        from app.models.base import resolve_pointer
        return resolve_pointer(raw, ptr['pointer'])
    except Exception:
        return None


def _data(value):
    return value.model_dump(mode='json') if hasattr(value, 'model_dump') else value

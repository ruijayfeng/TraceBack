"""Formal ⑨: membership of frozen ⑧ relations, with no relation inference.

The current stage-evidence-v2 contract uses candidate_id to address a decision.
Only its existing edges participate in connectivity; NO_RELATION and context
postings remain protected source data. Legacy str_* relations are also accepted
through their existing StageGraphSnapshot, without changing either contract.
"""
from collections import Counter, deque

from pydantic import Field, model_validator

from app.models.alerts import EvidencePointer
from app.models.base import Digest, StrictModel, UTCDateTime, id_type
from app.stages.models import StageID
from app.utils.stable_id import content_digest

DIRECTED = {'DIRECTED_EDGE', 'STRONG_DIRECTED', 'WEAK_DIRECTED'}
UNDIRECTED = {'UNDIRECTED_EDGE', 'STRONG_UNDIRECTED'}
VERSION = 'attack-chain-reconstruction-v1'


def data(value):
    return value.model_dump(mode='json') if hasattr(value, 'model_dump') else value


def field(value, name):
    return value[name] if isinstance(value, dict) else getattr(value, name)


def index(values, key):
    result = {field(v, key): v for v in values}
    if len(result) != len(values):
        raise ValueError('duplicate_stage9_reference:' + key)
    return result


class AttackChainMembership(StrictModel):
    chain_id: id_type('sch')
    stage_ids: list[StageID] = Field(min_length=1)
    # Existing scp_* decision IDs or legacy str_* relation IDs, never new edges.
    relation_ids: list[id_type('scp') | id_type('str')]
    single_stage: bool
    entry_stage_ids: list[StageID]
    exit_stage_ids: list[StageID]
    entry_exit_basis: str = 'existing_directed_relations_only'
    weak_direction_is_causal: bool = False
    has_directed_cycle: bool
    start_time: UTCDateTime
    end_time: UTCDateTime

    @model_validator(mode='after')
    def closure(self):
        for values in (self.stage_ids, self.relation_ids, self.entry_stage_ids, self.exit_stage_ids):
            if values != sorted(set(values)):
                raise ValueError('stage9_references_must_be_sorted_unique')
        identity = dict(version=VERSION, stage_ids=self.stage_ids, relation_ids=self.relation_ids)
        if self.chain_id != 'sch_' + content_digest(identity):
            raise ValueError('stage9_chain_identity_mismatch')
        if self.single_stage != (len(self.stage_ids) == 1) or self.single_stage and self.relation_ids:
            raise ValueError('stage9_single_stage_mismatch')
        if set(self.entry_stage_ids + self.exit_stage_ids) - set(self.stage_ids):
            raise ValueError('stage9_entry_exit_outside_chain')
        if self.entry_exit_basis != 'existing_directed_relations_only' or self.weak_direction_is_causal:
            raise ValueError('stage9_direction_semantics_mismatch')
        if self.start_time > self.end_time:
            raise ValueError('stage9_time_range_invalid')
        return self


class AttackChainReconstruction(StrictModel):
    contract_version: str = VERSION
    input_digest: Digest
    chains: list[AttackChainMembership]
    guard: dict


class FrozenStageGraph:
    """References to an already completed formal handoff, not a relation builder.

    Fingerprints cover the complete source, including negative decisions, all
    context/claim/observation/pointer tables, Stage metadata and raw Alerts.
    In-place mutation, removal, replacement and nested evidence edits fail closed.
    """
    def __init__(self, stages, relations, alerts, *, evidence=None, legacy=None):
        self.stages = index(list(stages), 'stage_id')
        self.alerts = index(list(alerts), 'alert_id')
        self.evidence = evidence
        self.legacy = legacy
        self.decisions = list(relations)
        self.relations = {}
        seen = set()
        for relation in self.decisions:
            row = data(relation)
            rid = row.get('relation_id', row.get('candidate_id'))
            if not rid or rid in seen:
                raise ValueError('duplicate_or_missing_stage9_relation_id')
            seen.add(rid)
            kind = row['relation_type']
            if kind not in DIRECTED | UNDIRECTED | {'NO_RELATION'}:
                raise ValueError('unknown_stage8_relation_type:' + kind)
            a, b = row['stage_a_id'], row['stage_b_id']
            if a == b or {a, b} - self.stages.keys():
                raise ValueError('dangling_or_invalid_stage9_endpoint:' + rid)
            source, target = row['from_stage_id'], row['to_stage_id']
            if kind in DIRECTED and {source, target} != {a, b}:
                raise ValueError('invalid_existing_directed_endpoints:' + rid)
            if kind not in DIRECTED and (source is not None or target is not None):
                raise ValueError('unresolved_existing_relation_has_arrows:' + rid)
            if kind != 'NO_RELATION':
                self.relations[rid] = relation
        self._frozen = self.signature()
        self.input_digest = self._frozen['input_digest']
        self.validate_evidence()
        self.assert_unchanged()

    @classmethod
    def from_stage8(cls, stages, evidence_result, alerts):
        if field(evidence_result, 'contract_version') != 'stage-evidence-v2':
            raise ValueError('requires_formal_stage8_v2_result')
        return cls(stages, field(evidence_result, 'decisions'), alerts, evidence=evidence_result)

    @classmethod
    def from_legacy(cls, snapshot):
        # Existing trace resolver owns the original Alerts and raw evidence.
        return cls(list(snapshot.stages.values()), list(snapshot.relations.values()), [], legacy=snapshot)

    def signature(self):
        rows = {rid: data(r) for rid, r in sorted(self.relations.items())}
        payload = dict(stages={k: data(v) for k, v in sorted(self.stages.items())},
            relations=rows, decisions=[data(r) for r in self.decisions],
            evidence=data(self.evidence), alerts={k: data(v) for k, v in sorted(self.alerts.items())},
            legacy_input=(dict(stages={k:data(v) for k,v in self.legacy.stages.items()},
                relations={k:data(v) for k,v in self.legacy.relations.items()},
                traces={k:data(v) for k,v in self.legacy.traces.items()}) if self.legacy else None))
        return dict(relation_count=len(rows), relation_ids=sorted(rows),
            relation_digest=content_digest(rows), input_digest=content_digest(payload))

    def assert_unchanged(self):
        current = self.signature()
        if current != self._frozen:
            raise ValueError('stage9_frozen_stage_relation_graph_modified')
        return dict(RELATION_COUNT_BEFORE=self._frozen['relation_count'],
            RELATION_COUNT_AFTER=current['relation_count'], RELATION_IDS_BEFORE=self._frozen['relation_ids'],
            RELATION_IDS_AFTER=current['relation_ids'],
            STAGE_RELATION_DIGEST_BEFORE=self._frozen['relation_digest'],
            STAGE_RELATION_DIGEST_AFTER=current['relation_digest'],
            RELATION_IDS_UNCHANGED=True, STAGE_RELATION_GRAPH_IMMUTABLE=True)

    def validate_evidence(self):
        """Resolve existing references only; never evaluate evidence semantics."""
        if self.legacy is not None:
            for ref in self.legacy.references(sorted(self.stages), sorted(self.relations)):
                self.legacy.resolve_trace(ref)
            return
        if self.evidence is None:
            raise ValueError('stage9_requires_existing_evidence_trace')
        for stage in self.stages.values():
            for aid in field(stage, 'alert_ids'):
                if aid not in self.alerts or field(self.alerts[aid], 'raw_alert') is None:
                    raise ValueError('dangling_stage_alert_or_raw_evidence')
        claims = index(list(field(self.evidence, 'claims')), 'claim_id')
        trace = field(self.evidence, 'trace')
        observations = index(list(field(trace, 'observations')), 'observation_id')
        pointers = index(list(field(trace, 'raw_pointers')), 'pointer_id')
        validations = index(list(field(trace, 'validations')), 'validation_id')
        contexts = index(list(field(self.evidence, 'context_postings')), 'context_identity_id')
        try:
            for ref in pointers.values():
                EvidencePointer.model_validate(data(field(ref, 'raw_pointer'))).resolve(self.alerts)
            for observation in observations.values():
                validations[field(observation, 'validation_id')]
                raw = [field(pointers[p], 'raw_pointer') for p in field(observation, 'raw_pointer_ids')]
                if {field(p, 'alert_id') for p in raw} != {field(observation, 'alert_a_id'), field(observation, 'alert_b_id')}:
                    raise ValueError('stage9_observation_pointer_endpoint_mismatch')
            for claim in claims.values():
                for oid in field(claim, 'observation_ids'):
                    observation = observations[oid]
                    for side in ('a', 'b'):
                        if field(observation, 'alert_' + side + '_id') not in field(self.stages[field(claim, 'stage_' + side + '_id')], 'alert_ids'):
                            raise ValueError('stage9_witness_outside_stage')
            for decision in self.decisions:
                for group in ('relation_claim_ids', 'context_claim_ids', 'supporting_claim_ids', 'invalid_claim_ids'):
                    for cid in field(decision, group):
                        claim = claims[cid]
                        if any(field(claim, 'stage_' + side + '_id') != field(decision, 'stage_' + side + '_id') for side in ('a', 'b')):
                            raise ValueError('stage9_claim_pair_mismatch')
                primary = field(decision, 'primary_claim_id')
                if primary is not None and primary not in field(decision, 'relation_claim_ids'):
                    raise ValueError('stage9_primary_claim_reference_missing')
                for cid in field(decision, 'context_identity_ids'):
                    contexts[cid]
            for context in contexts.values():
                for cid in field(context, 'evidence_claim_ids'):
                    claims[cid]
                for member in field(context, 'memberships'):
                    if field(member, 'alert_id') not in field(self.stages[field(member, 'stage_id')], 'alert_ids'):
                        raise ValueError('stage9_context_witness_outside_stage')
                    for pid in field(member, 'raw_pointer_ids'):
                        if field(field(pointers[pid], 'raw_pointer'), 'alert_id') != field(member, 'alert_id'):
                            raise ValueError('stage9_context_pointer_endpoint_mismatch')
        except (KeyError, IndexError) as exc:
            raise ValueError('dangling_stage9_evidence_reference') from exc


def components(graph):
    adjacency = {sid: set() for sid in graph.stages}
    for relation in graph.relations.values():
        a, b = field(relation, 'stage_a_id'), field(relation, 'stage_b_id')
        adjacency[a].add(b)
        adjacency[b].add(a)
    unseen, result = set(adjacency), []
    for root in sorted(adjacency):
        if root not in unseen:
            continue
        unseen.remove(root)
        members, queue = [], deque([root])
        while queue:
            sid = queue.popleft()
            members.append(sid)
            for neighbor in sorted(adjacency[sid] & unseen):
                unseen.remove(neighbor)
                queue.append(neighbor)
        result.append(sorted(members))
    return result


def arrow_metadata(members, relations):
    incoming, outgoing, participants = Counter(), {sid: [] for sid in members}, set()
    for relation in relations:
        if field(relation, 'relation_type') in DIRECTED:
            source, target = field(relation, 'from_stage_id'), field(relation, 'to_stage_id')
            incoming[target] += 1
            outgoing[source].append(target)
            participants.update((source, target))
    entries = sorted(s for s in participants if not incoming[s])
    exits = sorted(s for s in participants if not outgoing[s])
    queue, visited = deque(entries), 0
    while queue:
        sid = queue.popleft()
        visited += 1
        for target in outgoing[sid]:
            incoming[target] -= 1
            if not incoming[target]:
                queue.append(target)
    if len(members) == 1:
        entries = exits = list(members)
    return entries, exits, visited != len(participants)


def reconstruct_attack_chains(graph):
    """Each existing connected component becomes one membership record."""
    graph.assert_unchanged()
    try:
        membership = components(graph)
        owner = {sid: i for i, members in enumerate(membership) for sid in members}
        rids = {i: [] for i in range(len(membership))}
        for rid, relation in graph.relations.items():
            rids[owner[field(relation, 'stage_a_id')]].append(rid)
        chains = []
        for i, members in enumerate(membership):
            references = sorted(rids[i])
            entries, exits, cycle = arrow_metadata(members, [graph.relations[rid] for rid in references])
            chains.append(AttackChainMembership(
                chain_id='sch_' + content_digest(dict(version=VERSION, stage_ids=members, relation_ids=references)),
                stage_ids=members, relation_ids=references, single_stage=len(members) == 1,
                entry_stage_ids=entries, exit_stage_ids=exits, has_directed_cycle=cycle,
                start_time=min(field(graph.stages[s], 'start_time') for s in members),
                end_time=max(field(graph.stages[s], 'end_time') for s in members)))
        graph.validate_evidence()
        return AttackChainReconstruction(input_digest=graph.input_digest,
            chains=sorted(chains, key=lambda c: c.chain_id), guard=graph.assert_unchanged())
    finally:
        graph.assert_unchanged()


def validate_reconstruction(result, graph):
    """Check partitions, metadata, immutable source and complete raw trace."""
    graph.assert_unchanged()
    expected = reconstruct_attack_chains(graph)
    if result != expected:
        raise ValueError('stage9_chain_membership_or_metadata_mismatch')
    return dict(EVIDENCE_TRACE_PRESERVED=True, DANGLING_REFERENCE_COUNT=0)

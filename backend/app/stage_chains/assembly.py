"""Connected components of an existing mixed Stage graph; no edge decisions."""
from collections import Counter, deque
from dataclasses import dataclass

from .models import StageAttackChain, StageChainResult, chain_id


def connected_components(stage_ids, relations):
    adjacency = {sid:set() for sid in stage_ids}
    for relation in relations:
        a, b = relation.stage_a_id, relation.stage_b_id
        if a not in adjacency or b not in adjacency:
            raise ValueError('dangling_stage_reference:' + relation.relation_id)
        adjacency[a].add(b)
        adjacency[b].add(a)
    unseen = set(adjacency)
    components = []
    for root in sorted(adjacency):
        if root not in unseen:
            continue
        unseen.remove(root)
        members, queue = [], deque([root])
        while queue:
            sid = queue.popleft()
            members.append(sid)
            for neighbor in sorted(adjacency[sid]):
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    queue.append(neighbor)
        components.append(sorted(members))
    return components


def directed_shape(stage_ids, relations):
    """Entry/exit candidates use both existing arrow types, never undirected links.

    Kahn traversal only detects a cycle. It never deletes, reverses or sorts the
    actual graph into a path. Nodes lacking arrows are both entry/exit candidates.
    """
    incoming = {sid:0 for sid in stage_ids}
    outgoing = {sid:[] for sid in stage_ids}
    for relation in relations:
        if relation.relation_type == 'STRONG_UNDIRECTED':
            continue
        outgoing[relation.from_stage_id].append(relation.to_stage_id)
        incoming[relation.to_stage_id] += 1
    entries = sorted(sid for sid in stage_ids if not incoming[sid])
    exits = sorted(sid for sid in stage_ids if not outgoing[sid])
    queue = deque(entries)
    visited = 0
    while queue:
        sid = queue.popleft()
        visited += 1
        for target in sorted(outgoing[sid]):
            incoming[target] -= 1
            if incoming[target] == 0:
                queue.append(target)
    return entries, exits, visited != len(stage_ids)


def assemble_attack_chains(snapshot):
    components = connected_components(snapshot.stages, snapshot.relations.values())
    owner = {sid:i for i, members in enumerate(components) for sid in members}
    relations = {i:[] for i in range(len(components))}
    for relation in snapshot.relations.values():
        relations[owner[relation.stage_a_id]].append(relation)
    chains = []
    for i, members in enumerate(components):
        communities = {snapshot.stages[sid].community_id for sid in members}
        if len(communities) != 1:
            raise ValueError('connected_component_crosses_communities')
        community, = communities
        existing = relations[i]
        rids = sorted(r.relation_id for r in existing)
        counts = Counter(r.relation_type for r in existing)
        entries, exits, cycle = directed_shape(members, existing)
        chains.append(StageAttackChain(chain_id=chain_id(community, members, rids),
            source_analysis_id=snapshot.source_analysis_id, community_id=community,
            stage_ids=members, relation_ids=rids, stage_count=len(members), relation_count=len(rids),
            strong_directed_count=counts['STRONG_DIRECTED'], strong_undirected_count=counts['STRONG_UNDIRECTED'],
            weak_directed_count=counts['WEAK_DIRECTED'], entry_stage_ids=entries, exit_stage_ids=exits,
            single_stage=len(members)==1, has_directed_cycle=cycle, evidence_refs=snapshot.references(members, rids)))
    return StageChainResult(source_analysis_id=snapshot.source_analysis_id, input_digest=snapshot.input_digest,
                            chains=sorted(chains, key=lambda c:c.chain_id))


@dataclass
class AssemblyValidation:
    errors: list
    dangling_stage_reference_count: int = 0
    dangling_relation_reference_count: int = 0
    dangling_evidence_reference_count: int = 0
    raw_alerts_verified: int = 0
    evidence_pointers_resolved: int = 0

    @property
    def valid(self):
        return not self.errors

    def as_dict(self):
        return dict(valid=self.valid, **self.__dict__)

    def require_valid(self):
        if not self.valid:
            raise ValueError('stage_chain_validation_failed:' + str(self.errors))


def validate_assembly(result, snapshot):
    """Validate coverage, component membership and every existing trace to Raw.

    Counts describe missing submitted references. A dropped component or relation
    is separately reported as a partition error, never silently discarded.
    """
    report = AssemblyValidation([])
    covered_stages, covered_relations, raw_ids = [], [], set()
    def fail(code, cid=None):
        report.errors.append(dict(code=code, chain_id=cid))
    if result.source_analysis_id != snapshot.source_analysis_id or result.input_digest != snapshot.input_digest:
        fail('assembly_input_snapshot_mismatch')
    for chain in result.chains:
        cid = chain.chain_id
        covered_stages.extend(chain.stage_ids)
        covered_relations.extend(chain.relation_ids)
        missing_stages = set(chain.stage_ids) - snapshot.stages.keys()
        missing_relations = set(chain.relation_ids) - snapshot.relations.keys()
        report.dangling_stage_reference_count += len(missing_stages)
        report.dangling_relation_reference_count += len(missing_relations)
        if missing_stages:
            fail('dangling_stage_reference', cid)
        if missing_relations:
            fail('dangling_relation_reference', cid)
        for ref in chain.evidence_refs:
            try:
                trace = snapshot.resolve_trace(ref)
                raw_ids.update(trace.witness_alert_ids)
                report.evidence_pointers_resolved += len(trace.evidence_pointers)
            except (ValueError, KeyError, TypeError):
                report.dangling_evidence_reference_count += 1
                fail('dangling_evidence_reference', cid)
        try:
            StageAttackChain.model_validate(chain)
            if missing_stages or missing_relations:
                continue
            existing = [snapshot.relations[rid] for rid in chain.relation_ids]
            if any({r.stage_a_id, r.stage_b_id} - set(chain.stage_ids) for r in existing):
                fail('relation_endpoints_outside_chain', cid)
                continue
            if any(snapshot.stages[sid].community_id != chain.community_id for sid in chain.stage_ids):
                fail('chain_community_mismatch', cid)
            counts = Counter(r.relation_type for r in existing)
            if (chain.strong_directed_count, chain.strong_undirected_count, chain.weak_directed_count) != tuple(
                    counts[k] for k in ('STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED')):
                fail('chain_relation_counts_mismatch', cid)
            entries, exits, cycle = directed_shape(chain.stage_ids, existing)
            if (entries, exits, cycle) != (chain.entry_stage_ids, chain.exit_stage_ids, chain.has_directed_cycle):
                fail('chain_directed_shape_mismatch', cid)
            if chain.evidence_refs != snapshot.references(chain.stage_ids, chain.relation_ids):
                fail('chain_evidence_refs_differ_from_existing_traces', cid)
            snapshot.chain_trace(chain)
        except (ValueError, KeyError, TypeError):
            fail('chain_schema_or_trace_invalid', cid)
    if sorted(covered_stages) != sorted(snapshot.stages):
        fail('stage_partition_mismatch')
    if sorted(covered_relations) != sorted(snapshot.relations):
        fail('relation_partition_mismatch')
    components = connected_components(snapshot.stages, snapshot.relations.values())
    if sorted([c.stage_ids for c in result.chains]) != sorted(components):
        fail('chain_connected_component_membership_mismatch')
    try:
        StageChainResult.model_validate(result)
    except ValueError:
        fail('assembly_schema_invalid')
    report.raw_alerts_verified = len(raw_ids)
    return report

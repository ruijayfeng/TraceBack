"""Scoped Stage pair decisions, no multi-edge assembly or path search."""
from collections import Counter, defaultdict
from itertools import combinations

from app.community.models import IncidentCandidate
from app.stages.models import StageResult, Stage
from app.utils.stable_id import content_digest
from .evidence import evidence_for_pair, postings
from .models import DIRECTION_BASES, RelationConfidence, StageRelation, StageRelationResult, stable
from .time import time_facts


def analyze_stage_relations(stage_result, alerts, entities, communities, settings, community_config, policy):
    aa = {a.alert_id: a for a in alerts}
    ee = {e.entity_id: e for e in entities}
    cc = {c.community_id: c for c in communities}
    if len(aa) != len(alerts) or len(ee) != len(entities) or len(cc) != len(communities):
        raise ValueError('relation_input_ids_must_be_unique')
    if sorted(aid for c in communities for aid in c.alert_ids) != sorted(aa):
        raise ValueError('community_partition_must_cover_input_exactly_once')
    context = dict(alerts=aa, entities=ee, communities=cc)
    validated = StageResult.model_validate(stage_result, context=context)
    if sorted(aid for s in validated.stages for aid in s.alert_ids) != sorted(aa):
        raise ValueError('stage_partition_must_cover_input_exactly_once')
    for c in communities:
        IncidentCandidate.model_validate(c, context=context)
    for s in validated.stages:
        Stage.model_validate(s, context=context)
    context['stages'] = {s.stage_id:s for s in validated.stages}
    grouped = defaultdict(list)
    for stage in validated.stages:
        grouped[stage.community_id].append(stage)
    indexes = postings(validated.stages, aa, ee, settings, community_config)
    relations, diagnostics, counts = [], [], Counter()
    for cid in sorted(grouped):
        for a, b in combinations(sorted(grouped[cid], key=lambda s:s.stage_id), 2):
            counts['STAGE_PAIRS_CONSIDERED'] += 1
            candidates = evidence_for_pair(a, b, indexes, aa, ee, policy)
            diag = dict(community_id=cid, stage_a_id=a.stage_id, stage_b_id=b.stage_id,
                        evidence_candidate_count=len(candidates))
            if not candidates:
                counts['NO_RELATION_COUNT'] += 1
                diagnostics.append(dict(**diag, decision='NO_RELATION', reason='NO_ACTUAL_EVIDENCE'))
                continue
            primary = candidates[0]
            order, gap, overlap, conflict, consistency, facts = time_facts(a, b, primary, aa, policy)
            semantic = primary.semantic_direction
            opposite = [e for e in candidates if e.semantic_direction is not None and e.rank == primary.rank and
                e.evidence_strength == primary.evidence_strength and
                e.semantic_direction.from_stage_id != semantic.from_stage_id] if semantic else []
            direction_conflict = bool(opposite)
            if primary.strong:
                kind = 'STRONG_UNDIRECTED' if semantic is None or conflict or direction_conflict else 'STRONG_DIRECTED'
                src, dst = (None, None) if kind == 'STRONG_UNDIRECTED' else (semantic.from_stage_id, semantic.to_stage_id)
                reason = primary.reason + (' Strong association retained; shared identity provides no propagation direction.'
                    if semantic is None else ' Strong association retained; direction unresolved due to '+
                    ('TIME_CONFLICT.' if conflict else 'opposing equally ranked semantic evidence.')
                    if kind == 'STRONG_UNDIRECTED' else ' Semantic direction passes the independent time check.')
            elif not overlap:
                kind = 'WEAK_DIRECTED'
                src, dst = (a.stage_id, b.stage_id) if order == 'A_BEFORE_B' else (b.stage_id, a.stage_id)
                reason = primary.reason+' Weak association plus disjoint Stage observation order; does not prove causation.'
            else:
                counts['NO_RELATION_COUNT'] += 1
                diagnostics.append(dict(**diag, decision='NO_RELATION', reason='WEAK_EVIDENCE_WITHOUT_UNAMBIGUOUS_TIME_ORDER',
                    candidate_evidence=[e.model_dump(mode='json') for e in candidates]))
                continue
            reliable = kind != 'STRONG_UNDIRECTED'
            basis = RelationConfidence(evidence_strength=primary.evidence_strength,
                direction_reliability=primary.evidence_strength if reliable else 0.0,
                time_consistency=consistency,
                reason='Relation confidence equals the single primary evidence policy strength; direction and time are reported separately. Additional witnesses give no bonus.')
            data = dict(relation_id=stable('str', 'StageRelation', dict(community_id=cid, stage_ids=[a.stage_id,b.stage_id])),
                community_id=cid, stage_a_id=a.stage_id, stage_b_id=b.stage_id,
                from_stage_id=src, to_stage_id=dst, relation_type=kind, direction_reliable=reliable,
                direction_basis=DIRECTION_BASES[kind],
                primary_evidence=primary, supporting_evidence=candidates[1:],
                witness_alert_ids=sorted({aid for e in candidates for aid in e.alert_ids}),
                evidence_type=primary.evidence_type, evidence_strength=primary.evidence_strength,
                semantic_direction=semantic, observed_time_order=order, time_gap=gap, overlap=overlap,
                time_conflict=conflict, direction_conflict=direction_conflict, time_facts=facts,
                confidence=primary.evidence_strength, confidence_basis=basis, reason=reason)
            relation = StageRelation.model_validate(data, context=context)
            relations.append(relation)
            counts[kind+'_COUNT'] += 1
            diagnostics.append(dict(**diag, decision=kind, relation_id=relation.relation_id,
                selected_evidence_id=primary.evidence_id,
                ranked_evidence_ids=[e.evidence_id for e in candidates]))
    for key in ('STAGE_PAIRS_CONSIDERED', 'STRONG_DIRECTED_COUNT', 'STRONG_UNDIRECTED_COUNT', 'WEAK_DIRECTED_COUNT', 'NO_RELATION_COUNT'):
        counts.setdefault(key, 0)
    statistics = dict(INPUT_ALERTS=len(aa), COMMUNITY_COUNT=len(cc), STAGE_COUNT=len(validated.stages),
        **dict(counts), CURRENT_PIPELINE_STAGE='STAGE_LEVEL_ANALYSIS_COMPLETE',
        ATTACK_CHAIN_RECONSTRUCTION_STARTED=False, NEXT_STAGE_NOT_STARTED=True)
    stage_input = validated.model_dump(mode='json')
    stage_input['stages'] = sorted(stage_input['stages'], key=lambda s:s['stage_id'])
    stage_input['behaviors'] = sorted(stage_input['behaviors'], key=lambda s:s['alert_id'])
    digest = content_digest(dict(stages=stage_input,
        alerts=[aa[k].model_dump(mode='json') for k in sorted(aa)],
        entities=[ee[k].model_dump(mode='json') for k in sorted(ee)],
        communities=[cc[k].model_dump(mode='json') for k in sorted(cc)]))
    config_hash = content_digest(dict(stage_relations=policy.model_dump(mode='json'),
        community=community_config.model_dump(mode='json'), sources={k:v.snapshot() for k,v in settings.items()}))
    return StageRelationResult(config_hash=config_hash, input_digest=digest,
        relations=sorted(relations, key=lambda r:r.relation_id), diagnostics=diagnostics, statistics=statistics)

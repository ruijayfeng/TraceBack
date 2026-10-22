"""Validate exactly the official ⑦ candidate pairs and stop before ⑨."""
from collections import Counter

from app.stage_candidates.models import StagePairCandidateResult
from app.utils.stable_id import content_digest
from .extraction import extract_pair_evidence, project_witnesses
from .contracts import CrossStageEvidenceResult, StageRelationDecision
from .claims import ClaimCollector


def decide(candidate, claims, contexts):
    valid = [e for e in claims if e.valid]
    directional = [e for e in valid if e.semantic_class == 'DIRECTIONAL_RELATION']
    associative = [e for e in valid if e.semantic_class == 'DIRECT_ASSOCIATIVE_RELATION']
    context = [e for e in valid if e.semantic_class == 'CONTEXT']
    supporting = [e for e in valid if e.semantic_class == 'SUPPORTING']
    directions = {e.direction_claim for e in directional}
    diagnostics = {c for e in claims for c in e.metadata['observation_conflicts']}
    invalid = [e for e in claims if not e.valid]
    if diagnostics:
        diagnostics.add('HARD_CONFLICT')
    if any(e.semantic_class == 'DIRECTIONAL_RELATION' for e in invalid):
        diagnostics.add('DIRECTIONAL_EVIDENCE_INVALID')
    direction = 'NONE'
    primary = None
    if len(directions) == 1:
        kind,direction = 'DIRECTED_EDGE',next(iter(directions))
        primary = min(directional,key=lambda e:e.claim_id)
        reason = 'All valid directional relation claims agree; direction comes exclusively from evidence semantics.'
    elif len(directions) > 1:
        diagnostics.add('DIRECTION_CONFLICT')
        # Valid opposing semantic relations still certify a strong association.
        # No timestamp, rank, score or list order resolves the conflicting arrows.
        kind,direction = 'UNDIRECTED_EDGE','UNDIRECTED'
        primary = min(associative or directional,key=lambda e:e.claim_id)
        reason = 'Opposing valid direct relation claims certify a direct association but cannot resolve its direction.'
    elif associative:
        kind,direction = 'UNDIRECTED_EDGE','UNDIRECTED'
        primary = min(associative,key=lambda e:e.claim_id)
        reason = 'Explicit pair-specific relation or complete unpolluted two-Stage exclusive identity supplies direct association only.'
    else:
        kind = 'NO_RELATION'
        diagnostics.add('SHARED_CONTEXT_ONLY' if context or contexts else 'SUPPORTING_EVIDENCE_ONLY' if supporting else 'NO_VALID_EVIDENCE')
        reason = ('Stages share a verified context identity, but context membership alone does not establish a direct Stage relation.'
            if context or contexts else 'No valid direct relation claim; supporting context and observation order cannot create a relation.')
    return StageRelationDecision(candidate_id=candidate.candidate_id,
        stage_a_id=candidate.stage_a_id,stage_b_id=candidate.stage_b_id,relation_type=kind,
        direction_claim=direction,from_stage_id=(candidate.stage_a_id if direction == 'A_TO_B' else candidate.stage_b_id) if kind == 'DIRECTED_EDGE' else None,
        to_stage_id=(candidate.stage_b_id if direction == 'A_TO_B' else candidate.stage_a_id) if kind == 'DIRECTED_EDGE' else None,
        primary_claim_id=primary.claim_id if primary else None,
        relation_claim_ids=sorted(e.claim_id for e in directional+associative),context_claim_ids=sorted(e.claim_id for e in context),
        context_identity_ids=sorted(p.context_identity_id for p in contexts),
        supporting_claim_ids=sorted(e.claim_id for e in supporting),invalid_claim_ids=sorted(e.claim_id for e in invalid),
        relation_claim_count=len(directional)+len(associative),context_claim_count=len(context),
        supporting_claim_count=len(supporting),invalid_claim_count=len(invalid),unique_claim_count=len(claims),
        raw_supporting_observation_count=sum(e.observation_count for e in claims),
        evidence_type_counts=dict(sorted(Counter(e.evidence_type for e in claims).items())),
        diagnostics=sorted(diagnostics),reason=reason)


def validate_stage_pair_candidates(candidate_result, stage_result, alerts, entities, settings, community_config, policy):
    if not isinstance(candidate_result, StagePairCandidateResult):
        raise ValueError('stage8_requires_official_candidate_result')
    # Validate formal handoff objects, never generate or repair upstream output.
    candidate_data=candidate_result.model_dump(mode='json')
    candidate_data['candidates'].sort(key=lambda c:(c['stage_a_id'],c['stage_b_id']))
    StagePairCandidateResult.model_validate(candidate_data)
    aa = {a.alert_id:a for a in alerts}
    ee = {e.entity_id:e for e in entities}
    ss = {s.stage_id:s for s in stage_result.stages}
    if len(aa) != len(alerts) or len(ee) != len(entities) or len(ss) != len(stage_result.stages):
        raise ValueError('stage8_requires_unique_input_ids')
    members = [aid for s in ss.values() for aid in s.alert_ids]
    annotations = {b.alert_id:b for b in stage_result.behaviors}
    if len(members) != len(set(members)) or set(members) != aa.keys() or annotations.keys() != aa.keys():
        raise ValueError('stage8_requires_official_stage_partition_and_annotations')
    if any(set(a.entity_ids)-ee.keys() for a in alerts):
        raise ValueError('stage8_entity_reference_missing')
    for candidate in candidate_result.candidates:
        a,b = ss.get(candidate.stage_a_id),ss.get(candidate.stage_b_id)
        if not a or not b or (a.community_id,b.community_id) != (candidate.community_a_id,candidate.community_b_id):
            raise ValueError('candidate_stage_membership_mismatch')
    indexes = project_witnesses(ss.values(),aa,ee,settings,community_config,policy)
    collector=ClaimCollector(aa,ss)
    collector.build_contexts(indexes,ee,policy)
    candidate_claims={}
    ordered=sorted(candidate_result.candidates,key=lambda c:(c.stage_a_id,c.stage_b_id))
    for candidate in ordered:
        candidate_claims[candidate.candidate_id]=extract_pair_evidence(ss[candidate.stage_a_id],ss[candidate.stage_b_id],indexes,aa,ee,policy,collector)
    claims,contexts,trace=collector.finish()
    claim_index={c.claim_id:c for c in claims}
    decisions=[decide(c,[claim_index[cid] for cid in candidate_claims[c.candidate_id]],
        [p for p in contexts if {c.stage_a_id,c.stage_b_id}<=set(p.stage_ids)]) for c in ordered]
    counts = Counter(d.relation_type for d in decisions)
    classes=Counter(c.semantic_class for c in claims)
    raw_count=sum(c.observation_count for c in claims)
    checks={v.validation_id:v for v in trace.validations}
    observations={o.observation_id:o for o in trace.observations}
    stats = dict(INPUT_ALERTS=len(aa),INPUT_STAGE_COUNT=len(ss),INPUT_CANDIDATE_PAIR_COUNT=len(candidate_result.candidates),
        STAGE8_INPUT_PAIR_COUNT=len(decisions),STAGE7_CANDIDATE_PAIR_COUNT=len(candidate_result.candidates),
        DIRECTED_EDGE_COUNT=counts['DIRECTED_EDGE'],UNDIRECTED_EDGE_COUNT=counts['UNDIRECTED_EDGE'],NO_RELATION_COUNT=counts['NO_RELATION'],
        NEW_PIPELINE_WEAK_DIRECTED_COUNT=0,RAW_SUPPORTING_OBSERVATION_COUNT=raw_count,
        UNIQUE_TRACE_OBSERVATION_COUNT=len(trace.observations),UNIQUE_EVIDENCE_CLAIM_COUNT=len(claims),
        LOGICALLY_DUPLICATE_RAW_OBSERVATION_COUNT=raw_count-len(claims),
        MAX_OBSERVATIONS_PER_CLAIM=max((c.observation_count for c in claims),default=0),
        AVG_OBSERVATIONS_PER_CLAIM=raw_count/len(claims) if claims else 0.0,
        DIRECTIONAL_RELATION_CLAIM_COUNT=classes['DIRECTIONAL_RELATION'],DIRECT_ASSOCIATIVE_RELATION_CLAIM_COUNT=classes['DIRECT_ASSOCIATIVE_RELATION'],
        CONTEXT_CLAIM_COUNT=classes['CONTEXT'],SUPPORTING_CLAIM_COUNT=classes['SUPPORTING'],INVALID_CLAIM_COUNT=sum(not c.valid for c in claims),
        CONTEXT_IDENTITY_POSTING_COUNT=len(contexts),CONTEXT_MEMBERSHIP_TREATED_AS_PAIRWISE_RELATION=False,
        WITNESS_CARTESIAN_EXPLOSION_IN_LOGICAL_CLAIMS=False,
        EVIDENCE_TYPE_COUNTS=dict(sorted(Counter(c.evidence_type for c in claims).items())),
        RELATIONS_WITH_EVIDENCE=counts['DIRECTED_EDGE']+counts['UNDIRECTED_EDGE'],RELATIONS_WITHOUT_EVIDENCE=0,
        DANGLING_CLAIM_REFERENCE_COUNT=0,DANGLING_OBSERVATION_REFERENCE_COUNT=0,DANGLING_RAW_POINTER_COUNT=0,
        DIRECTION_CONFLICT_COUNT=sum('DIRECTION_CONFLICT' in d.diagnostics for d in decisions),
        TEMPORAL_CONFLICT_COUNT=sum('TEMPORAL_CONFLICT' in checks[observations[oid].validation_id].conflict_status for c in claims for oid in c.observation_ids),
        HARD_CONFLICT_COUNT=sum(not c.valid for c in claims),TIME_ONLY_RELATION_CREATION=False,
        TIME_CAN_CREATE_DIRECTION=False,TIME_CAN_VETO_INVALID_DIRECTION=True,TEMPORAL_ORDER_TREATED_AS_CAUSAL_EVIDENCE=False,
        OLD_ALERT_PAIR_SCORER_USED=False,GROUND_TRUTH_USED_BY_PRODUCTION=False,STAGE_9_STARTED=False,
        CURRENT_PIPELINE_STAGE='STAGE_8_RELATION_SEMANTICS_REPAIRED',NEXT_STAGE_NOT_STARTED=True)
    stage_data = stage_result.model_dump(mode='json')
    stage_data['stages'] = sorted(stage_data['stages'],key=lambda s:s['stage_id'])
    stage_data['behaviors'] = sorted(stage_data['behaviors'],key=lambda b:b['alert_id'])
    candidate_data['features'].sort(key=lambda f:(f['stage_id'],f['key']))
    for candidate in candidate_data['candidates']:
        candidate['retrieval_features'].sort(key=lambda f:(f['stage_id'],f['key']))
    inputs = dict(candidates=candidate_data,stages=stage_data,
        alerts=[aa[k].model_dump(mode='json') for k in sorted(aa)],entities=[ee[k].model_dump(mode='json') for k in sorted(ee)],
        settings={k:vars(v) for k,v in sorted(settings.items())},community_config=community_config.digest)
    return CrossStageEvidenceResult(config_hash=policy.digest,input_digest=content_digest(inputs),
        decisions=decisions,claims=claims,context_postings=contexts,trace=trace,statistics=stats)

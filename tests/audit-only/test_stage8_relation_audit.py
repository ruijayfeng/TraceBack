"""Diagnostic invariants against the frozen 42-Stage audit; no data edits."""
from copy import deepcopy
from itertools import combinations
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'backend'))
from audit_stage8_relation_sparsity import (GeneratorTrace, distribution, quantile,
    rejection_reason, validate_report)

OUT=ROOT/'outputs/stage8_relation_sparsity_audit'


def load(name):
    return json.loads((OUT/name).read_text(encoding='utf8'))


@pytest.fixture(scope='module')
def audit():
    return dict(summary=load('summary.json'),stages=load('stages.json'),pairs=load('pairs.json'),
        decisions=load('decisions.json'),isolated=load('isolated_stages.json'))


def test_complete_pair_space_and_two_funnels(audit):
    assert validate_report(audit)
    summary=audit['summary']
    assert (summary['TOTAL_POSSIBLE_STAGE_PAIRS'],summary['STAGE7_CANDIDATE_PAIR_COUNT'],
        summary['STAGE8_ACCEPTED_RELATION_COUNT'],summary['STAGE8_REJECTED_PAIR_COUNT'])==(861,165,23,142)
    assert {(r['stage_a'],r['stage_b']) for r in audit['pairs']}==set(combinations(sorted(s['stage_id'] for s in audit['stages']),2))


def test_stage_inventory_uses_original_data_and_degree(audit):
    handoff=json.loads((ROOT/'outputs/stage2_identity_projection/after.json').read_text(encoding='utf8'))
    original={s['stage_id']:s for s in handoff['stages']['stages']}
    for row in audit['stages']:
        source=original[row['stage_id']]
        assert all(row[key]==source[key] for key in ('community_id','alert_count','start_time','end_time','behavior','alert_ids'))
        degree=sum(row['stage_id'] in (d['stage_a'],d['stage_b']) for d in audit['decisions'] if d['decision']!='NO_RELATION')
        assert row['stage8_degree']==degree
        assert row['ISOLATED_IN_STAGE8_GRAPH']==(degree==0)


def test_every_noncandidate_has_observed_or_absence_reason(audit):
    for row in audit['pairs']:
        events=row['original_generator_events']
        assert {e['key'] for e in events}==set(row['shared_existing_feature_keys'])
        assert row['candidate']==any(e['outcome']=='NOMINATED' for e in events)
        if not row['candidate']:
            assert row['rejection_reason']
            if not events:assert row['rejection_reason']==['NO_SHARED_RETRIEVAL_KEY']
        for event in events:
            path=ROOT/event['code_path']['file']
            assert path.read_text(encoding='utf8').splitlines()[event['code_path']['line']-1].strip()==event['code_path']['executed_instruction']


def test_original_generator_is_instrumented_without_reimplementation():
    from app.stage_candidates.generator import generate_stage_pair_candidates
    tracer=GeneratorTrace(generate_stage_pair_candidates)
    assert tracer.code is generate_stage_pair_candidates.__code__
    assert list(tracer.actions.values()).count('ROLE')==2


def test_every_decision_and_evidence_is_original(audit):
    source=json.loads((ROOT/'outputs/stage2_identity_projection/after.json').read_text(encoding='utf8'))['evidence']
    decisions={r['candidate_id']:r for r in source['decisions']}
    claims={r['claim_id']:r for r in source['claims']}
    for row in audit['decisions']:
        assert row['formal_decision']==decisions[row['relation_id']]
        assert all(c==claims[c['claim_id']] for c in row['formal_claims'])


def test_terminal_rejection_not_confused_with_incidental_diagnostic():
    assert rejection_reason(dict(relation_type='NO_RELATION',diagnostics=['HARD_CONFLICT','SHARED_CONTEXT_ONLY']))=='SHARED_CONTEXT_ONLY'
    assert rejection_reason(dict(relation_type='UNDIRECTED_EDGE',diagnostics=['DIRECTION_CONFLICT'])) is None
    with pytest.raises(ValueError,match='formal_rejection'):
        rejection_reason(dict(relation_type='NO_RELATION',diagnostics=['HARD_CONFLICT']))


def test_true_rejection_reasons_and_claim_classification(audit):
    assert audit['summary']['REJECT_REASON_COUNTS']=={'SHARED_CONTEXT_ONLY':138,'NO_VALID_EVIDENCE':4}
    for row in audit['decisions']:
        if row['decision']=='NO_RELATION':
            assert not row['valid_directional_claims'] and not row['valid_associative_relation_claims']
            assert not row['formal_decision']['relation_claim_ids']


def test_zero_candidate_and_all_rejected_isolation_are_distinct(audit):
    zero=[r for r in audit['isolated'] if not r['candidate_pair_count']]
    rejected=[r for r in audit['isolated'] if r['candidate_pair_count']]
    assert len(zero)==1 and len(rejected)==23
    assert zero[0]['stage_id']=='stg_7e951854ce84eec740043576654349ff11fa133b153bec8c5a3ca811c912175e'
    assert all(r['possible_pair_count']==41 and r['candidate_pair_count']==r['rejected_pair_count'] for r in audit['isolated'])


def test_temporal_posting_visits_not_misreported_as_pair_loss(audit):
    summary=audit['summary']
    assert summary['STAGE7_TEMPORAL_PRUNED_POSTING_PAIR_VISITS']==15
    assert summary['STAGE7_PAIRS_WITH_ANY_TEMPORAL_PRUNING']==13
    assert summary['PAIRS_REJECTED_BY_TEMPORAL_CONSTRAINT']==1
    zero=next(r for r in audit['isolated'] if not r['candidate_pair_count'])
    assert zero['all_eligible_shared_postings_filtered_by_time']
    events=[e for r in audit['pairs'] if not r['candidate'] for e in r['original_generator_events'] if e['outcome']=='EXCLUDED_BY_TIME']
    assert len(events)==1 and events[0]['gap_seconds']==460 and events[0]['window_seconds']==120


def test_community_boundary_does_not_filter_candidates(audit):
    s=audit['summary']
    assert (s['THEORETICAL_SAME_COMMUNITY_PAIR_COUNT'],s['THEORETICAL_CROSS_COMMUNITY_PAIR_COUNT'])==(316,545)
    assert (s['CROSS_COMMUNITY_CANDIDATE_COUNT'],s['CROSS_COMMUNITY_ACCEPTED_COUNT'])==(7,4)
    assert s['PAIRS_EXCLUDED_BY_COMMUNITY_BOUNDARY']==0


def test_projection_loss_requires_existing_missing_witness():
    projection=load('projection_audit.json')
    assert projection['potential_losses']==[]
    assert projection['noncandidate_pairs_with_existing_typed_stage8_postings']==[]
    direct=[r for r in projection['binding_observations'] if r['status']=='PRESERVED_TYPED_BINDING']
    assert len(direct)==402 and all(r['stage8_observation_hits'] and r['stage7_feature_keys'] for r in direct)
    assert all(r['stage_summary_preserved'] is not False for r in projection['entity_summary_checks'])
    assert all(m['canonical_entity_in_alert'] for b in projection['identity_projection_checks'] for m in b['members'])


def test_network_hint_does_not_certify_cross_source_binding():
    rows=load('network_scope_audit.json')
    assert len(rows)==4
    for row in rows:
        assert row['candidate_reason']==['SHARED_CONNECTION_TOKEN_AND_ENDPOINT_PAIR']
        assert row['original_decision']['relation_type']=='NO_RELATION'
        assert row['original_decision']['unique_claim_count']==0
        assert all(a['declared_network_namespace'] is None for side in row['endpoints'] for a in side['alerts'])


def test_unknown_direction_and_hard_conflicts(audit):
    s=audit['summary']
    assert s['HARD_CONFLICT_PAIR_COUNT']==s['REJECTED_DUE_TO_DIRECTION_REQUIREMENT']==0
    assert s['RELATION_PRESENT_BUT_DIRECTION_UNKNOWN_PAIR_COUNT']==s['ACCEPTED_AS_STRONG_UNDIRECTED']==1
    undirected=next(r for r in audit['decisions'] if r['decision']=='UNDIRECTED_EDGE')
    assert undirected['formal_decision']['from_stage_id'] is undirected['formal_decision']['to_stage_id'] is None


def test_no_legacy_weak_path_or_stage9_executed(audit):
    s=audit['summary'];execution=load('execution.json')
    assert s['WEAK_DIRECTED_IMPLEMENTED'] is s['WEAK_DIRECTED_ENABLED'] is False
    assert s['WEAK_DIRECTED_PATH_REACHED_COUNT']==0
    assert execution['replay_stage7_exact'] and execution['replay_stage8_exact']
    assert not any(k.startswith(('app.stage_relations','app.stage_chains')) for k in execution['replay_calls'])


def test_accepted_main_evidence_count_is_exclusive(audit):
    s=audit['summary']
    assert s['ACCEPTED_RELATION_PRIMARY_EVIDENCE_USAGE']=={'PARENT_CHILD_PROCESS':12,'AUTH_ESTABLISH_USE':9,'OBJECT_HANDOFF':1,'SAME_STRONG_SESSION':1}
    assert sum(s['ACCEPTED_RELATION_PRIMARY_EVIDENCE_USAGE'].values())==23
    assert sum(s['ACCEPTED_RELATION_EVIDENCE_USAGE'].values())>23


def test_quantiles_include_min_median_p75_p90_max_and_empty_values():
    assert distribution([0,10])==dict(count=2,min=0,median=5,p75=7.5,p90=9,max=10)
    assert quantile([], .75) is None
    assert distribution([])['median'] is None


@pytest.mark.parametrize('key', ['STAGE7_NON_CANDIDATE_PAIR_COUNT','STAGE8_INPUT_PAIR_COUNT','STAGE8_ACCEPTED_RELATION_COUNT'])
def test_report_validator_rejects_inconsistent_funnel(audit,key):
    bad=deepcopy(audit)
    bad['summary'][key]+=1
    with pytest.raises(AssertionError):validate_report(bad)


def test_existing_source_and_data_integrity():
    integrity=load('integrity.json')
    assert integrity['FILES_CHANGED_FROM_BASELINE']==[]
    assert integrity['FROZEN_HANDOFF_UNCHANGED'] and integrity['STAGE9_CODE_AND_ARTIFACTS_UNCHANGED']
    assert integrity['STAGE_RELATION_DIGEST_BEFORE']==integrity['STAGE_RELATION_DIGEST_AFTER']

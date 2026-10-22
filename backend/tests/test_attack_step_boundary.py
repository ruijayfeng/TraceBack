"""Candidate retention / boundary tests for MEMBERSHIP_EVIDENCE_MODEL and
STEP_BOUNDARY_MODEL. Synthetic typed facts; no Ground Truth inputs.

These tests assert the core invariant introduced by the boundary fix:

    RELATION_EVIDENCE != MEMBERSHIP_EVIDENCE

i.e. a valid accepted relation, shared flow/session, shared host/account, or
temporal proximity alone can never retain a multi-member Candidate. A whole
group membership anchor (shared strong identity binding) is required.
"""
import copy
import json
import os
import sys

import pytest

if os.environ.get('TRACEBACK_SCHEMA_VALIDATOR_PATH'):
    sys.path.insert(0, os.environ['TRACEBACK_SCHEMA_VALIDATOR_PATH'])

from app.attack_steps.candidate import generate
from app.attack_steps.evidence import checked_reference
from app.attack_steps.grouping import build_groups, evaluate
from app.attack_steps.membership import (
    boundary_breaches,
    common_membership_anchors,
    identity_match_kind,
    same_step_retainable,
)
from app.attack_steps.models import Proposal, run_id
from app.attack_steps.validation import envelope

# Reuse the synthetic fixture helpers from the prototype test module.
import test_attack_step_prototype as base


def _evaluate(s, members=None, kind=None):
    members = members or tuple(sorted(s.indexes['stage']))
    return evaluate(s, Proposal(tuple(sorted(members)), ('SYNTHETIC_TEST',), kind),
                    run_id(envelope(s)))


# --- identity UNKNOWN / MATCH / CONFLICT --------------------------------

def test_identity_unknown_when_kind_none():
    s = base.synthetic()
    kind, contradictions = identity_match_kind(s, sorted(s.indexes['stage']), None)
    assert kind == 'UNKNOWN' and not contradictions


def test_identity_unknown_when_not_observed_on_all_members():
    s = base.synthetic(count=3)
    # Remove request context from the third alert so 'request' is not observed
    # on its member; identity must be UNKNOWN, never MATCH.
    s.stage8['alerts'][2]['contexts'] = []
    base.refresh(s)
    kind, contradictions = identity_match_kind(s, sorted(s.indexes['stage']), 'request')
    assert kind == 'UNKNOWN'


def test_identity_match_when_same_value_observed_on_all_members():
    s = base.synthetic()
    kind, contradictions = identity_match_kind(s, sorted(s.indexes['stage']), 'request')
    assert kind == 'MATCH' and not contradictions


def test_identity_conflict_when_distinct_values_one_scope():
    s = base.synthetic()
    s.stage8['alerts'][1]['contexts'][0]['value'] = 'different'
    s.stage8['alerts'][1]['raw_alert']['request_id'] = 'different'
    base.refresh(s)
    kind, contradictions = identity_match_kind(s, sorted(s.indexes['stage']), 'request')
    assert kind == 'CONFLICT' and contradictions


def _strip_anchors(s):
    """Remove strong identity bindings so only relation/context remains."""
    for st in s.stage8['stages']['stages']:
        st['request_bindings'] = []
        st['task_bindings'] = []
    base.refresh(s)


# --- relation evidence never forms membership ---------------------------

def test_relation_only_is_not_membership_anchor():
    s = base.synthetic(p1=False)  # PARENT_CHILD claim, valid relation
    _strip_anchors(s)
    members = sorted(s.indexes['stage'])
    # A valid accepted relation exists but no strong identity binding; the
    # membership anchor must be empty.
    assert common_membership_anchors(s, members) == []


def test_relation_only_cannot_retain_candidate():
    s = base.synthetic(p1=False)
    _strip_anchors(s)
    members = sorted(s.indexes['stage'])
    retainable, detail = same_step_retainable(s, members, None)
    assert retainable is False
    assert detail['membership_anchor_keys'] == []
    g, l = _evaluate(s)
    assert g['membership_status'] == 'UNRESOLVED'


def test_shared_flow_and_web_shape_cannot_retain_candidate():
    s = base.synthetic(p1=False)
    base.no_relations(s)
    _strip_anchors(s)
    for st in s.stage8['stages']['stages']:
        st['flow_bindings'] = ['flow:shared']
    for al in s.stage8['alerts']:
        al.update(url='/observed', alert_type='alert')
    base.refresh(s)
    g, l = _evaluate(s)
    # Shared flow + web shape is relation/context evidence, never membership.
    assert g['membership_status'] == 'UNRESOLVED'


def test_shared_session_cannot_retain_candidate():
    s = base.synthetic(p1=False)
    base.no_relations(s)
    _strip_anchors(s)
    for st in s.stage8['stages']['stages']:
        st['session_bindings'] = ['session:shared']
    base.refresh(s)
    g, l = _evaluate(s)
    assert g['membership_status'] == 'UNRESOLVED'


# --- group-level coherence ----------------------------------------------

def test_shared_request_binding_is_membership_anchor():
    s = base.synthetic(p1=False)
    for st in s.stage8['stages']['stages']:
        st['request_bindings'] = ['request:shared-scoped-identity']
    base.refresh(s)
    members = sorted(s.indexes['stage'])
    assert common_membership_anchors(s, members) == ['request:shared-scoped-identity']


def test_group_with_anchor_and_relation_retains_candidate():
    s = base.synthetic(p1=False)
    for st in s.stage8['stages']['stages']:
        st['request_bindings'] = ['request:shared-scoped-identity']
    base.refresh(s)
    g, l = _evaluate(s)
    assert g['membership_status'] == 'CANDIDATE'
    assert g['grouping_basis']['reason_codes'] == ['PURPOSE_NOT_PROVEN']


def test_partial_anchor_is_not_whole_group_anchor():
    # Only one member has the request binding; no whole-group anchor.
    s = base.synthetic(count=3, p1=False)
    s.stage8['stages']['stages'][0]['request_bindings'] = ['request:only-one']
    base.refresh(s)
    members = sorted(s.indexes['stage'])
    assert common_membership_anchors(s, members) == []
    g, l = _evaluate(s)
    assert g['membership_status'] == 'UNRESOLVED'


# --- STEP_BOUNDARY_MODEL breach detection -------------------------------

def test_boundary_breach_no_common_anchor():
    s = base.synthetic(p1=False)
    _strip_anchors(s)
    members = sorted(s.indexes['stage'])
    breaches, detail = boundary_breaches(s, members, None)
    assert 'NO_COMMON_MEMBERSHIP_ANCHOR' in breaches
    assert 'RELATION_ONLY_MEMBERSHIP' in breaches


def test_boundary_breach_identity_conflict():
    s = base.synthetic()
    s.stage8['alerts'][1]['contexts'][0]['value'] = 'different'
    s.stage8['alerts'][1]['raw_alert']['request_id'] = 'different'
    base.refresh(s)
    breaches, detail = boundary_breaches(s, sorted(s.indexes['stage']), 'request')
    assert 'IDENTITY_CONFLICT' in breaches


def test_boundary_breach_disconnected_induced():
    s = base.synthetic(count=3, p1=False)
    base.no_relations(s)
    for st in s.stage8['stages']['stages']:
        st['request_bindings'] = ['request:shared']
    base.refresh(s)
    members = sorted(s.indexes['stage'])
    breaches, detail = boundary_breaches(s, members, None)
    # With no accepted relation, the induced graph is disconnected.
    assert 'DISCONNECTED_INDUCED' in breaches


def test_identity_unknown_is_not_positive_anchor():
    # UNKNOWN identity alone (kind set but not observed on all members) must
    # not become a positive membership anchor.
    s = base.synthetic(count=3)
    _strip_anchors(s)
    s.stage8['alerts'][2]['contexts'] = []
    base.refresh(s)
    members = sorted(s.indexes['stage'])
    retainable, detail = same_step_retainable(s, members, 'request')
    # With a request hypothesis but no observed identity + no anchor, it is
    # not retainable.
    assert retainable is False
    kind, _ = identity_match_kind(s, members, 'request')
    assert kind == 'UNKNOWN'


# --- evidence pointer regression ----------------------------------------

def test_membership_model_does_not_break_evidence_refs():
    s = base.synthetic(p1=False)
    for st in s.stage8['stages']['stages']:
        st['request_bindings'] = ['request:shared']
    base.refresh(s)
    g, l = _evaluate(s)
    assert all(checked_reference(s, r)['resolution'] == 'RESOLVED' for r in g['evidence_refs'])

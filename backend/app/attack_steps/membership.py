"""MEMBERSHIP_EVIDENCE_MODEL and STEP_BOUNDARY_MODEL.

Separates evidence that explains *why observations belong to the same bounded
Attack Step* (membership anchor) from evidence that only explains *that two
observations are related* (relation evidence).

Invariant enforced by the retention gate in grouping.evaluate:

    RELATION_EVIDENCE != MEMBERSHIP_EVIDENCE

A group of stages may only be retained as a multi-member CANDIDATE when a
common, whole-group membership anchor is present. A valid accepted relation,
shared flow/session, shared host/account, temporal proximity, or process
lineage alone is relation evidence and can never, by itself, certify that
several stages belong to the same Attack Step.

Nothing here invents a field that does not exist in the sealed inputs. Every
anchor is read from existing stage8/stage9 objects.
"""
from collections import defaultdict

from .models import jcs

# --- Anchor kinds ---------------------------------------------------------

# A binding key that identifies a *scoped identity* shared verbatim across
# stages. These are strong membership anchors: they carry a typed authority
# scope, so equal keys imply the same principal/request/task identity, not
# merely the same network context.
ANCHOR_BINDING_FIELDS = ('request_bindings', 'task_bindings')

# Binding keys that only describe shared environment / lifecycle context.
# They are relation evidence, never membership evidence on their own.
CONTEXT_BINDING_FIELDS = ('flow_bindings', 'session_bindings')

# A request binding whose key denotes a *complete scoped* request identity
# (authority domain + host scope) is the strongest same-step anchor. A bare
# request token without a scope is not an anchor.
def is_anchor_binding(field):
    return field in ANCHOR_BINDING_FIELDS


def stage_anchors(stage):
    """Return {field: sorted(binding_keys)} for strong-identity bindings."""
    result = {}
    for field in ANCHOR_BINDING_FIELDS:
        result[field] = sorted(stage.get(field, []))
    return result


def stage_contexts(stage):
    """Return {field: sorted(binding_keys)} for weak context bindings."""
    result = {}
    for field in CONTEXT_BINDING_FIELDS:
        result[field] = sorted(stage.get(field, []))
    return result


# --- Identity match / conflict / unknown ---------------------------------

def identity_match_kind(s, members, kind):
    """Classify an explicit identity hypothesis across member stages.

    Returns ('MATCH'|'CONFLICT'|'UNKNOWN', contradictions).
    UNKNOWN means the identity is not observably present on every member; it
    is absence of evidence, never NO_CONFLICT, and is not a positive anchor.
    """
    if not kind:
        return 'UNKNOWN', []
    buckets = defaultdict(lambda: defaultdict(list))
    observed = set()
    for sid in members:
        for aid in s.indexes['stage'][sid]['alert_ids']:
            for context in s.indexes['alert'][aid]['contexts']:
                if context['kind'] != kind:
                    continue
                observed.add(sid)
                buckets[context['scope']][str(context['value'])].append(aid)
    contradictions = []
    status = 'UNKNOWN'
    if observed == set(members):
        # Identity observed on every member. Distinct values within one scope
        # is a real conflict; a single shared value is a match.
        per_scope = {scope: len(values) for scope, values in buckets.items()}
        if any(n > 1 for n in per_scope.values()):
            status = 'CONFLICT'
            for scope, values in sorted(buckets.items()):
                if len(values) > 1:
                    contradictions.append(dict(
                        code='INCOMPATIBLE_ACTIVITY_IDENTITY',
                        detail='Explicit same-' + kind + ' hypothesis has distinct observed values in one existing scope: ' + scope,
                        evidence_refs=[]))
        else:
            status = 'MATCH'
    return status, contradictions


# --- Whole-group membership anchor ---------------------------------------

def common_membership_anchors(s, members):
    """Compute the whole-group membership anchor, if any.

    A membership anchor is a strong identity shared by *every* member stage.
    Only strong-identity binding fields (request/task) qualify. Returns a
    sorted list of shared anchor keys (e.g. ['request:<digest>', ...]).

    Weak context (flow/session) and shared entities are deliberately excluded:
    they are relation evidence.
    """
    member_stages = [s.indexes['stage'][sid] for sid in members]
    shared = {}
    for field in ANCHOR_BINDING_FIELDS:
        sets = [set(st.get(field, [])) for st in member_stages]
        common = set.intersection(*sets) if sets else set()
        shared[field] = sorted(common)
    anchors = []
    for field in ANCHOR_BINDING_FIELDS:
        for key in shared[field]:
            anchors.append(key)
    return sorted(anchors)


def relation_evidence_summary(s, members):
    """Summarize relation evidence present among members (never an anchor)."""
    member_set = set(members)
    accepted = [d for d in s.indexes['accepted'].values()
                if {d['stage_a_id'], d['stage_b_id']} <= member_set]
    relation_types = sorted({d['relation_type'] for d in accepted})
    shared_flow = bool(common_context_keys(s, members, 'flow_bindings'))
    shared_session = bool(common_context_keys(s, members, 'session_bindings'))
    return dict(accepted_relation_count=len(accepted),
                relation_types=relation_types,
                shared_flow=shared_flow,
                shared_session=shared_session)


def common_context_keys(s, members, field):
    member_stages = [s.indexes['stage'][sid] for sid in members]
    sets = [set(st.get(field, [])) for st in member_stages]
    return set.intersection(*sets) if sets else set()


# --- STEP_BOUNDARY_MODEL -------------------------------------------------

def boundary_breaches(s, members, identity_kind):
    """Return the list of STEP_BOUNDARY_MODEL conditions violated by a group.

    Each breach means the group must NOT be retained as a same-step CANDIDATE
    (it is demoted to UNRESOLVED unless a whole-group membership anchor and an
    explicit MATCH identity hold).

    Breach codes:
      NO_COMMON_MEMBERSHIP_ANCHOR  - no strong identity shared by all members;
                                      relation/context alone cannot certify one
                                      step.
      IDENTITY_CONFLICT             - explicit same-identity hypothesis is
                                      observably contradicted.
      IDENTITY_UNKNOWN_NOT_ANCHOR  - identity is absent on some member; absence
                                      is not NO_CONFLICT and not a positive
                                      anchor (but does not alone force split).
      CROSS_CHAIN                   - members span multiple reconstructed
                                      Chains; Chain partitions relatedness.
      DISCONNECTED_INDUCED          - members are not connected in the accepted
                                      induced graph (bridge-node-only linkage).
      RELATION_ONLY_MEMBERSHIP      - the only basis for grouping is relation
                                      evidence (no anchor).
    """
    breaches = []
    anchors = common_membership_anchors(s, members)
    if not anchors:
        breaches.append('NO_COMMON_MEMBERSHIP_ANCHOR')
    match_kind, contradictions = identity_match_kind(s, members, identity_kind)
    if match_kind == 'CONFLICT':
        breaches.append('IDENTITY_CONFLICT')
    elif match_kind == 'UNKNOWN' and identity_kind:
        breaches.append('IDENTITY_UNKNOWN_NOT_ANCHOR')
    chains = {s.indexes['chain_owner'][sid] for sid in members}
    if len(chains) > 1:
        breaches.append('CROSS_CHAIN')
    # Induced connectivity via accepted relations only.
    adjacency = {sid: set() for sid in members}
    for d in s.indexes['accepted'].values():
        a, b = d['stage_a_id'], d['stage_b_id']
        if a in adjacency and b in adjacency:
            adjacency[a].add(b); adjacency[b].add(a)
    seen = set(); components = []
    for sid in members:
        if sid in seen:
            continue
        frontier = [sid]; comp = set()
        while frontier:
            cur = frontier.pop()
            if cur in comp:
                continue
            comp.add(cur); frontier.extend(sorted(adjacency[cur] - comp))
        seen |= comp; components.append(comp)
    if len(components) > 1:
        breaches.append('DISCONNECTED_INDUCED')
    if not anchors:
        breaches.append('RELATION_ONLY_MEMBERSHIP')
    return breaches, dict(match_kind=match_kind, contradictions=contradictions,
                          anchors=anchors, components=[sorted(c) for c in components])


def same_step_retainable(s, members, identity_kind):
    """Group-level gate: can this member set be retained as one Attack Step?

    Returns (retainable: bool, detail: dict).

    A multi-member group is retainable only when it has a whole-group
    membership anchor AND no explicit identity conflict. UNKNOWN identity is
    tolerated only when a concrete anchor exists (absence of identity is not
    itself disqualifying); without any anchor it cannot be retained.
    """
    anchors = common_membership_anchors(s, members)
    match_kind, contradictions = identity_match_kind(s, members, identity_kind)
    retainable = bool(anchors) and match_kind != 'CONFLICT'
    return retainable, dict(
        membership_anchor_keys=anchors,
        identity_kind=identity_kind,
        identity_status=match_kind,
        contradictions=contradictions)

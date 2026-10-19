"""Pure, identity-blind, interpretable formulas on an explicit evidence envelope.

Provenance is output-only: no identifier, pointer text or entity value is inspected
in score(). Projection reads frozen canonical occurrence ROLES and shared identity
membership, not raw payload, detector strings, dataset markers or truth sidecars.
"""
from dataclasses import dataclass, replace
import math


STATES = {'SUPPORT', 'OBSERVED_ZERO', 'UNAVAILABLE', 'CONTRADICTORY', 'NOT_APPLICABLE', 'AMBIGUOUS'}


@dataclass(frozen=True)
class Evidence:
    name: str
    family: str
    state: str
    strength: float
    reliability: float
    provenance: tuple = ()
    role: str = 'generic'
    weight: float = 1.
    original_strength: float | None = None

    def __post_init__(self):
        if self.state not in STATES or not all(math.isfinite(x) and 0 <= x <= 1 for x in (self.strength, self.reliability)):
            raise ValueError('invalid_evidence')
        if self.state != 'SUPPORT' and self.strength:
            raise ValueError('non_support_strength')


@dataclass(frozen=True)
class Envelope:
    evidence: tuple[Evidence, ...]
    conflicts: tuple
    duplicate: float
    duplicate_risk: bool
    old_gate: bool
    v4_score: float
    v4_positive: float
    v4_conflict: float
    family_weights: tuple


def conflict_classification(conflicts):
    """No different target representation proves exclusive endpoint identity."""
    result = []
    for rule in conflicts.get('hard', []):
        result.append(dict(kind='HARD_CONTRADICTION', rule=rule, strength=1., provenance=[]))
    left, right = conflicts.get('left_targets', []), conflicts.get('right_targets', [])
    for rule, strength in conflicts.get('soft', []):
        kind = 'SOFT_INCONSISTENCY'
        if rule == 'different_target_without_bridge':
            kinds_l = {x['key'][0] for x in left}
            kinds_r = {x['key'][0] for x in right}
            kind = 'REPRESENTATION_DIFFERENCE' if kinds_l.isdisjoint(kinds_r) else 'UNKNOWN_EQUIVALENCE'
        result.append(dict(kind=kind, rule=rule, strength=strength,
                           provenance=[p for x in left + right for p in x['raw_pointers']]))
    return tuple(result)


def incompatible_identity_proof(*, left, right, role, scope, context, moment, provenance):
    """Synthetic typed proof seam; canonical v1 has no such exclusivity proof.

    Identity inequality alone is insufficient. Caller must provide a bound,
    same-role/scope/context/instant exclusivity assertion from a trusted source.
    This seam is tested but is NEVER populated by raw alert dictionary keys.
    """
    if not all((role, scope, context, moment, len(provenance) >= 2)) or left == right:
        raise ValueError('unproven_exclusivity')
    return dict(kind='HARD_CONTRADICTION', rule='verified_exclusive_endpoint_identity',
                strength=1., provenance=list(provenance))


def project(row, alerts, policy):
    audit = row['evidence']['evidence_v2']
    a, b = (alerts[x] for x in row['support_pair'])
    occurrences = []
    for alert in (a, b):
        by_id = {}
        for o in alert['entity_occurrences']:
            by_id.setdefault(o['entity_id'], []).append(o)
        occurrences.append(by_id)
    ev = []
    state_map = {'AVAILABLE_MATCH': 'SUPPORT', 'AVAILABLE_MISMATCH': 'OBSERVED_ZERO',
                 'UNAVAILABLE': 'UNAVAILABLE', 'NOT_APPLICABLE': 'NOT_APPLICABLE'}
    for d in audit['dimensions']:
        name, family = d['dimension'], d['family']
        strength, role = d['strength'], 'generic'
        reliability = policy['reliability']['generic'].get(name.removeprefix('entity.'),
            policy['reliability'].get({'time':'time', 'behavior':'metadata', 'relation':'attested_relation', 'source':'source'}.get(family, 'generic_fallback'), .1))
        refs = []
        for eid in d['entity_ids']:
            la, rb = (o.get(eid, []) for o in occurrences)
            lr, rr = {x['role'] for x in la}, {x['role'] for x in rb}
            refs.extend({'alert_id':alert['alert_id'], 'pointer':x['raw_pointer'], 'side':'shared'}
                        for alert, os in ((a,la),(b,rb)) for x in os)
            if name == 'entity.HOST' and 'host' in lr & rr:
                role, reliability = 'host', policy['reliability']['role_host']
            elif name == 'entity.ACCOUNT' and any(
                {l,r} <= {'authenticated_account','target_account','source_account','audit_account'}
                for l in lr for r in rr):
                role, reliability = 'account', policy['reliability']['role_account']
                # Explicit compatible subject roles replace v4's generic other-role
                # factor; rarity is retained and never replaced with a GT prior.
                record = next((x for x in audit['entity_reliability'] if x['entity_id']==eid), None)
                if record and record['role_factor']:
                    strength = min(1., strength / record['role_factor'])
            elif name == 'entity.IP' and 'monitored_host_ip' in lr | rr:
                if 'monitored_host_ip' in lr & rr or ('monitored_host_ip' in lr and rr & {'src_ip','dst_ip'}) or ('monitored_host_ip' in rr and lr & {'src_ip','dst_ip'}):
                    role, reliability = 'endpoint', policy['reliability']['monitored_endpoint']
                    record = next((x for x in audit['entity_reliability'] if x['entity_id']==eid), None)
                    if record and record['role_factor']:
                        strength = min(1., strength / record['role_factor'])
        if family == 'relation' and strength:
            role = 'direct' if name == 'topology.attested_relation' else 'flow'
        if not refs:
            fields = ['timestamp'] if family == 'time' else ['category','rule_id','signature'] if family == 'behavior' else []
            refs = [dict(alert_id=x['alert_id'],pointer=x['field_provenance'][f]['raw_pointer'],side='shared')
                    for x in (a,b) for f in fields if f in x['field_provenance']]
        # Attested relation refs are already verified and bound in frozen input.
        if family == 'relation' and strength:
            refs += [p for r in row['evidence']['relations'] for p in r['raw_pointers']]
        ev.append(Evidence(name,family,state_map[d['state']],strength,reliability,tuple(refs),role,d['weight'],d['strength']))
    w = audit['family_weights']
    positive = audit['quality_factor']*audit['normalized_quality']+audit['mass_factor']*audit['evidence_mass']
    return Envelope(tuple(ev), conflict_classification(row['evidence']['conflicts']),
                    row['values']['duplicate'],audit['duplicate_observation_risk'],audit['evidence_gate_passed'],
                    row['score'],positive,row['values']['conflict'],tuple(sorted(w.items())))


def score(envelope, policy, model='F3', ablation=None, gate_mode='hybrid'):
    if model not in {'F0','F1','F2','F3'} or gate_mode not in {'hard','soft','hybrid'}:
        raise ValueError('unknown_formula_or_gate')
    evidence = envelope.evidence
    if ablation == 'remove_time': evidence = tuple(e for e in evidence if e.family != 'time')
    role_aware = model in {'F2','F3'} and ablation != 'remove_role_aware_entity'
    rows = []
    for e in evidence:
        if not role_aware and e.family == 'entity':
            e = replace(e, strength=e.original_strength if e.original_strength is not None else e.strength,
                        reliability=policy['reliability']['generic'][e.name[7:]], role='generic')
        rows.append(e)
    available = [e for e in rows if e.state in {'SUPPORT','OBSERVED_ZERO','CONTRADICTORY'}]
    supports = [e for e in available if e.state == 'SUPPORT']
    semantic = [e for e in supports if e.family in {'entity','relation'}]
    contextual = [e for e in semantic if e.role in {'host','account','endpoint','direct','flow'}]
    direct = any(e.role == 'direct' for e in semantic)
    joint = any(e.role=='host' for e in semantic) and any(e.role=='account' for e in semantic)
    # A common safety ceiling uses observed semantic facts, independently of
    # whether a candidate formula rewards their roles in its additive terms.
    original_semantic=[e for e in envelope.evidence if e.state=='SUPPORT' and e.family in {'entity','relation'}]
    original_joint=any(e.role=='host' for e in original_semantic) and any(e.role=='account' for e in original_semantic)
    original_direct=any(e.role=='direct' for e in original_semantic)
    weak_only = not original_direct and not original_joint and not any(e.family=='entity' and e.name in {'entity.SESSION','entity.PROCESS'} and e.strength>=policy['strong_identifier_minimum'] and envelope.old_gate for e in semantic)
    temporal = next((e.strength for e in rows if e.family=='time'),1.)
    bonuses, penalties = [], []
    if model == 'F0':
        support, coverage, before_penalties = envelope.v4_positive, 1., envelope.v4_positive
    elif model == 'F1':
        # Quality-only available FAMILY normalization, v4 weights/strengths.
        fw = dict(envelope.family_weights)
        fs = {}
        for family in fw:
            ds=[e for e in available if e.family==family]
            if ds: fs[family]=max(e.strength for e in ds) if family=='relation' else math.fsum(e.weight*e.strength for e in ds)/math.fsum(e.weight for e in ds)
        den=math.fsum(fw[f] for f in fs)
        support=math.fsum(fw[f]*s for f,s in fs.items())/den if den else 0.
        coverage=1.;before_penalties=support
    else:
        ds = [e for e in available if e.family != 'time']
        den=math.fsum(e.reliability*e.weight for e in ds)
        support=math.fsum(e.reliability*e.weight*e.strength for e in ds)/den if den else 0.
        # Confidence uses independent semantic types, excluding time/metadata/source.
        # HOST and monitored IP describe the same asset and count only once.
        masses={}
        for e in semantic:
            key='asset' if e.role in {'host','endpoint'} else e.name
            masses[key]=max(masses.get(key,0.),e.reliability*e.strength)
        coverage=min(1.,math.fsum(masses.values())/policy['semantic_mass_reference']) if model=='F3' and ablation!='remove_coverage_confidence' else 1.
        compatibility=1. if ablation=='remove_time' else policy['time_floor']+(1-policy['time_floor'])*temporal
        before_penalties=support*coverage*compatibility
        if model=='F3' and ablation!='remove_interactions':
            host=max((e.strength for e in semantic if e.role=='host'),default=0.)
            account=max((e.strength for e in semantic if e.role=='account'),default=0.)
            role=max((e.strength for e in contextual),default=0.)
            source=max((e.strength for e in supports if e.family=='source'),default=0.)
            terms={'host_account':host*account,'role_time':role*temporal if ablation!='remove_time' else 0.,'source_entity':source*role}
            bonuses=[dict(name=k,contribution=policy['interactions'][k]*v*coverage) for k,v in terms.items() if v]
            extra=min(policy['interaction_cap'],math.fsum(b['contribution'] for b in bonuses))
            before_penalties+=extra
    conflicts=envelope.conflicts
    hard=any(c['kind']=='HARD_CONTRADICTION' for c in conflicts)
    if model=='F0' or ablation=='remove_conflict_redesign':
        cp=policy['conflict_weight']*envelope.v4_conflict
    else:
        cp=max((policy['conflict_weight']*c['strength'] if c['kind']=='HARD_CONTRADICTION' else
                policy['soft_penalty']*c['strength'] if c['kind']=='SOFT_INCONSISTENCY' else 0. for c in conflicts),default=0.)
    dp=policy['duplicate_weight']*envelope.duplicate
    penalties=[dict(name='conflict',contribution=cp),dict(name='duplicate',contribution=dp)]
    pre_cap=max(0.,min(1.,before_penalties-cp-dp))
    final=envelope.v4_score if model=='F0' else min(pre_cap,policy['weak_ceiling']) if weak_only else pre_cap
    non_time=bool(semantic)
    strong=bool(direct or joint)
    gate=(non_time and not hard and not envelope.duplicate_risk)
    if model in {'F0','F1'}:gate &= envelope.old_gate
    elif gate_mode=='hard':gate &= strong
    elif gate_mode=='soft' and not strong:final*=policy['gate_soft_factor']
    elif gate_mode=='hybrid':gate &= bool(contextual or strong)
    if model!='F0' and (not non_time or hard or envelope.duplicate_risk):final=0.
    def view(e):return dict(name=e.name,family=e.family,state=e.state,strength=e.strength,reliability=e.reliability,role=e.role,weight=e.weight,provenance=list(e.provenance))
    return dict(final_score=final,support_score=support,coverage_confidence=coverage,
        positive_support=before_penalties,pre_ceiling_score=pre_cap,conflict_penalty=cp,
        duplicate_penalty=dp,temporal_compatibility=temporal,
        supporting_evidence=[view(e) for e in supports if e in semantic],
        weak_evidence=[view(e) for e in supports if e not in semantic],
        unavailable_evidence=[view(e) for e in rows if e.state in {'UNAVAILABLE','NOT_APPLICABLE'}],
        observed_zero_evidence=[view(e) for e in rows if e.state=='OBSERVED_ZERO'],
        contradictions=list(conflicts),bonuses=bonuses,penalties=penalties,
        gates=dict(non_temporal_semantics=non_time,strong_semantics=strong,weak_only=weak_only,
                   mode=gate_mode,passed=bool(gate),old_gate=envelope.old_gate,hard=hard,duplicate_risk=envelope.duplicate_risk),
        reference_admitted=bool(gate and final>=policy['threshold']))

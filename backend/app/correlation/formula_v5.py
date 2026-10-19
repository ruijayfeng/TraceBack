"""Identity-blind F3: reliable semantic groups, alternative proof pathways.

Values are support indices, not calibrated probabilities. No labels, detector
strings, entity values or provenance text enter the arithmetic.
"""
import math

ALGORITHM_VERSION = 'alert-correlation-v5-f3-independent-support-v1'
IMPLEMENTATION_VERSION = 'v5-formula-f3-v1'


def aggregate(features, policy, *, hard, duplicate_risk, duplicate):
    if policy['formula'] == 'evidence-semantics-v1':
        return aggregate_semantics(features, policy, hard=hard, duplicate_risk=duplicate_risk, duplicate=duplicate)
    groups = {}
    direct = 0.
    for f in features:
        if f['state'] != 'SUPPORTED' or f['family'] not in {'entity', 'relation'}:
            continue
        value = f['strength'] * f['reliability']
        if f['role'] == 'direct':
            direct = max(direct, value)
            continue
        key = 'asset' if f['role'] in {'host', 'endpoint'} else f['name']
        groups[key] = max(groups.get(key, 0.), value)
    # Max per group: repeated packaging and host/IP aliases cannot reinforce.
    mass = 1 - math.prod(1-v for _,v in sorted(groups.items()))
    quality = max([direct, *groups.values()], default=0.)
    time = max((f['strength'] for f in features if f['family']=='time' and f['state']=='SUPPORTED'), default=0.)
    temporal_factor = policy['time_floor'] + (1-policy['time_floor'])*time
    contextual = {f['role'] for f in features if f['state']=='SUPPORTED' and f['family']=='entity' and not f['hot']}
    strong_identifier = any(f['name'] in {'entity.SESSION','entity.PROCESS'} and f['state']=='SUPPORTED'
        and f['strength'] >= policy['strong_identifier_minimum'] and not f['hot'] for f in features)
    # Two different context types may corroborate; HOST+IP still only one asset.
    strong = direct > 0 or strong_identifier or ('account' in contextual and bool(contextual & {'host','endpoint'}))
    positive = max(direct, mass*temporal_factor)
    conflict = max((f['reliability'] for f in features if f['state']=='CONTRADICTED'),default=0.)
    penalty = policy['conflict_weight']*conflict
    duplicate_penalty = policy['duplicate_weight']*duplicate
    raw = positive-penalty-duplicate_penalty
    final = min(1.,max(0.,raw))
    if not strong:
        final = min(final,policy['weak_ceiling'])
    semantic = bool(groups or direct)
    passed = semantic and not hard and not duplicate_risk
    if not passed:
        final = 0.
    return dict(group_support=dict(sorted(groups.items())),direct_support=direct,
        evidence_mass=mass,quality=quality,temporal_factor=temporal_factor,
        positive_support=positive,conflict_penalty=penalty,duplicate_penalty=duplicate_penalty,
        raw_total=raw,final_score=final,weak_only=not strong,
        gate=dict(passed=passed,hard_contradiction=bool(hard),duplicate_observation=bool(duplicate_risk),
            non_temporal_support=semantic))


SEMANTICS_VERSION = 'alert-correlation-v5-evidence-semantics-v1'
SEMANTICS_IMPLEMENTATION = 'v5-evidence-semantics-v1'


def identity(policy):
    return ((SEMANTICS_VERSION, SEMANTICS_IMPLEMENTATION) if policy['formula']=='evidence-semantics-v1'
            else (ALGORITHM_VERSION, IMPLEMENTATION_VERSION))


def independent_groups(features):
    """Conservative dependency components, independent of evidence packaging.

    An address/endpoint/host view is one asset clue; URL/domain one resource;
    process/file/command one execution clue. Shared entity IDs join any remaining
    derived views. Max within each component prevents duplicated full credit.
    """
    selected=[f for f in features if f['state']=='OBSERVED_SUPPORT' and
              f['family'] in {'entity','relation'} and f['role']!='direct']
    selected.sort(key=lambda f:f['name'])
    components=[]
    for f in selected:
        kind=f['name'].removeprefix('entity.')
        key=('asset' if kind in {'IP','HOST'} or f['role'] in {'endpoint','flow','host'} else
             'resource' if kind in {'DOMAIN','URL'} else
             'execution' if kind in {'PROCESS','FILE','COMMAND'} else f['name'])
        ids=set(f['entity_ids']); matched=[]
        for i,(keys,eids,fs) in enumerate(components):
            if key in keys or ids & eids: matched.append(i)
        keys={key}; fs=[f]
        for i in reversed(matched):
            ks,es,old=components.pop(i); keys.update(ks); ids.update(es); fs.extend(old)
        components.append((keys,ids,fs))
    return sorted(components,key=lambda c:sorted(c[0]))


def aggregate_semantics(features, policy, *, hard, duplicate_risk, duplicate):
    groups={}; reliable_groups=set(); agreement_terms=[]
    for keys,ids,fs in independent_groups(features):
        key='+'.join(sorted(keys))
        best=min(fs,key=lambda f:(-f['strength']*f['reliability'],f['name']))
        groups[key]=best['strength']*best['reliability']
        agreement_terms.append((best['strength'],best['reliability']))
        if any(not f['hot'] and f['strength']*f['reliability']>0 for f in fs): reliable_groups.add(key)
    supported=[f for f in features if f['state']=='OBSERVED_SUPPORT']
    direct=max((f['strength']*f['reliability'] for f in supported if f['role']=='direct'),default=0.)
    mass=1-math.prod(1-v for _,v in sorted(groups.items()))
    denominator=math.fsum(w for s,w in agreement_terms)
    agreement=math.fsum(s*w for s,w in agreement_terms)/denominator if denominator else 0.
    temporal=max((f['strength'] for f in supported if f['family']=='time'),default=0.)
    temporal_factor=policy['time_floor']+(1-policy['time_floor'])*temporal
    strong_identifier=any(f['name'] in {'entity.SESSION','entity.PROCESS'} and
        f['strength']>=policy['strong_identifier_minimum'] and not f['hot'] for f in supported)
    strong=direct>0 or strong_identifier or len(reliable_groups)>=2
    positive=max(direct,mass*temporal_factor)
    conflict=max((f['reliability'] for f in features if f['state']=='OBSERVED_CONTRADICTION'),default=0.)
    penalty=policy['conflict_weight']*conflict
    duplicate_penalty=policy['duplicate_weight']*duplicate
    raw=positive-penalty-duplicate_penalty
    final=min(1.,max(0.,raw))
    if not strong: final=min(final,policy['weak_ceiling'])
    semantic=bool(any(v>0 for v in groups.values()) or direct)
    passed=semantic and not hard and not duplicate_risk
    if not passed: final=0.
    return dict(group_support=dict(sorted(groups.items())),direct_support=direct,
        evidence_mass=mass,quality=agreement,temporal_factor=temporal_factor,
        positive_support=positive,conflict_penalty=penalty,duplicate_penalty=duplicate_penalty,
        raw_total=raw,final_score=final,weak_only=not strong,
        gate=dict(passed=passed,hard_contradiction=bool(hard),duplicate_observation=bool(duplicate_risk),
                  non_temporal_support=semantic))

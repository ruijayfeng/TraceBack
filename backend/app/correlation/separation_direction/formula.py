"""Replace the value of a contextual proof under a grounded transition.

No new independent component is added: context equality and the role/behavior
interpretation of that equality occupy the same dependency group.
"""
import math


def aggregate(baseline,groups,transition,policy):
    upgraded=dict(groups)
    if transition:
        kind=transition['context']['kind']
        key='asset' if kind in {'IP','HOST'} else 'entity.'+kind
        if key in upgraded:
            upgraded[key]=max(upgraded[key],policy['transition_ceiling']*
                transition['compatibility']*transition['specificity'])
    mass=1-math.prod(1-v for _,v in sorted(upgraded.items()))
    positive=max(baseline['direct_support'],mass*baseline['temporal_factor'])
    raw=positive-baseline['conflict_penalty']-baseline['duplicate_penalty']
    score=max(0.,min(1.,raw))
    # A specific role-grounded transition is a sufficient alternative to the
    # old single-clue cap. Common entity equality has no such pathway.
    if baseline['weak_only'] and not transition:score=min(score,policy['weak_ceiling'])
    if not baseline['gate']['passed']:score=0.
    return dict(group_support=dict(sorted(groups.items())),upgraded_group_support=dict(sorted(upgraded.items())),
        evidence_mass=mass,temporal_factor=baseline['temporal_factor'],direct_support=baseline['direct_support'],
        conflict_penalty=baseline['conflict_penalty'],duplicate_penalty=baseline['duplicate_penalty'],
        raw_total=raw,final_score=score,gate=baseline['gate'],transition=transition,
        baseline_weak_only=baseline['weak_only'],weak_only=baseline['weak_only'] and not bool(transition))

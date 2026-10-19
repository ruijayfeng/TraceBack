"""Three prospective dependency-preserving ceiling semantics; no label inputs."""
import math


def aggregate(baseline, groups, tier, policy, design):
    if design not in {'A', 'B', 'C'}:
        raise ValueError('unknown_semantic_design')
    upgraded = dict(groups)
    bound = tier['level'] == 3 and tier['progression_proven'] and not tier['contradiction']
    partial = tier['observed_behavior_transition'] and tier['verified_role_bridge'] and not tier['contradiction']
    replacement = bound or (design == 'B' and partial)
    context = tier['context']
    if replacement and context and tier['behavior_evidence']:
        key = 'asset' if context['kind'] in {'IP', 'HOST'} else 'entity.'+context['kind']
        if key in upgraded:
            compatibility = max(t['compatibility'] for t in tier['behavior_evidence'])
            upgraded[key] = max(upgraded[key], policy['transition_ceiling']*compatibility*context['specificity'])
    mass = 1-math.prod(1-v for _, v in sorted(upgraded.items()))
    positive = max(baseline['direct_support'], mass*baseline['temporal_factor'])
    raw = positive-baseline['conflict_penalty']-baseline['duplicate_penalty']
    ceiling = 1.
    reason = 'baseline_independent_context_support'
    if baseline['weak_only']:
        ceiling = policy['weak_ceiling']; reason = 'context_or_compatibility_cannot_unlock'
        if bound and design in {'A', 'B'}:
            ceiling = 1.; reason = 'verified_bound_transition'
        elif design == 'B' and partial:
            ceiling = policy['partial_ceiling']; reason = 'observed_behavior_and_role_partial_ceiling'
        elif design == 'C':
            reason = 'quality_adjustment_retains_weak_ceiling'
    score = min(ceiling, max(0., min(1., raw))) if baseline['gate']['passed'] else 0.
    return dict(design=design, group_support=dict(sorted(groups.items())),
                upgraded_group_support=dict(sorted(upgraded.items())), evidence_mass=mass,
                temporal_factor=baseline['temporal_factor'], direct_support=baseline['direct_support'],
                conflict_penalty=baseline['conflict_penalty'], duplicate_penalty=baseline['duplicate_penalty'],
                positive_support=positive, raw_total=raw, ceiling=ceiling, ceiling_decision=reason,
                gate=baseline['gate'], final_score=score)


def chain_admission(score, directional, tier, gate, policy, variant):
    """Independent semantic admission; component/interval/DAG checks follow it."""
    cp = policy['chain_admission_policy']
    verified = directional['status'] == 'DERIVED_VERIFIED_DIRECTION'
    clean = gate['passed'] and not directional['contradiction'] and not tier['contradiction']
    confidence = directional['direction_confidence']
    strong = score >= cp['strong_correlation'] and confidence >= cp['minimum_direction']
    moderate = score >= cp['moderate_correlation'] and confidence >= cp['minimum_direction']
    bound = tier['level'] == 3 and tier['progression_proven']
    if variant == 'A': accepted = strong
    elif variant == 'B': accepted = moderate
    elif variant == 'C': accepted = moderate and bound
    elif variant == 'D':
        accepted = strong or (moderate and bound and confidence >= cp['high_direction'])
    else: raise ValueError('unknown_chain_policy')
    accepted = bool(accepted and verified and clean)
    return dict(policy=variant, accepted=accepted,
                path=('strong_correlation_verified_direction' if strong else 'bound_moderate_context') if accepted else None,
                reason='semantic_admission_passed' if accepted else
                'gate_or_contradiction' if not clean else 'direction_unverified' if not verified else 'confidence_or_tier',
                correlation_confidence=score, direction_confidence=confidence, transition_level=tier['level'])

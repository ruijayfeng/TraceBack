"""Identity-blind experimental arithmetic, with role-aware dependency groups.

Only project() can see canonical identity references. score() accepts numbers,
states and evidence classes, never alert IDs, raw pointers, labels or sources.
These research results are not production ScoreBreakdown objects.
"""
import math

SUPPORT = 'OBSERVED_SUPPORT'


def roles(alert, entity_id):
    return {o['role'] for o in alert['entity_occurrences'] if o['entity_id'] == entity_id}


def project(row, alerts, entities):
    a, b = [alerts[i] for i in row['support_pair']]
    v5 = row['evidence']['evidence_v5']
    shared = set(a['entity_ids']) & set(b['entity_ids'])
    features = []
    bindings = []
    for original in v5['features']:
        f = {k: original[k] for k in ('name', 'family', 'state', 'strength', 'reliability', 'hot', 'role')}
        kind = f['name'].removeprefix('entity.')
        ids = shared & set(original['entity_ids'])
        f['parent_only'] = bool(ids) and kind == 'PROCESS' and all(
            roles(a, i) == {'parent_process'} and roles(b, i) == {'parent_process'} for i in ids)
        f['anchor_kind'] = None
        if kind == 'SESSION' and ids:
            kinds = set()
            for i in ids:
                try:
                    scope = __import__('json').loads(entities[i]['scope'])
                    kinds.add(scope.get('identity_kind', 'untyped'))
                except (ValueError, TypeError):
                    kinds.add('untyped')
            # Exact existing scoped identity only, no equivalence inferred here.
            f['anchor_kind'] = 'session' if kinds - {'untyped'} else None
            bindings.extend(dict(entity_id=i, type='SESSION', roles_a=sorted(roles(a, i)),
                                 roles_b=sorted(roles(b, i)), scope=entities[i]['scope']) for i in sorted(ids))
        elif kind == 'PROCESS' and ids and not f['parent_only']:
            valid = []
            for i in ids:
                try:
                    value = __import__('json').loads(entities[i]['value'])
                except (ValueError, TypeError):
                    continue
                if isinstance(value, dict) and value.get('pid') is not None and value.get('start_time') and value.get('host'):
                    valid.append(i)
            if valid:
                f['anchor_kind'] = 'process'
            bindings.extend(dict(entity_id=i, type='PROCESS', roles_a=sorted(roles(a, i)),
                                 roles_b=sorted(roles(b, i)), parent_only=f['parent_only']) for i in sorted(ids))
        if f['role'] == 'direct' and f['state'] == SUPPORT:
            f['anchor_kind'] = 'attested_relation'
        features.append(f)
    return dict(features=features, gate=v5['gate'], valid=row['valid'],
                duplicate=v5['duplicate'], conflict_penalty=v5['conflict_penalty'],
                duplicate_penalty=v5['duplicate_penalty']), bindings


def score(environment, policy, model):
    if model not in {'A', 'B', 'C'}:
        raise ValueError('unknown_model')
    groups = {}
    weights = {}
    anchors = {}
    time = 0.
    neutral = 0
    audit = []
    for f in sorted(environment['features'], key=lambda f: f['name']):
        state = f['state']
        if f['family'] == 'time' and state == SUPPORT:
            time = max(time, f['strength'])
        if f['family'] not in {'entity', 'relation'}:
            continue
        if state in {'MISSING', 'UNOBSERVABLE'}:
            continue
        if state == 'OBSERVED_NEUTRAL':
            neutral += 1
            continue
        if state != SUPPORT:
            continue
        kind = f['name'].removeprefix('entity.')
        # Infrastructure views and derived resource names share one context.
        group = ('context' if kind in {'IP', 'HOST', 'URL', 'DOMAIN'} or f['role'] == 'flow' else
                 'execution' if kind in {'PROCESS', 'FILE', 'COMMAND'} else
                 'identity' if kind == 'ACCOUNT' else 'session' if kind == 'SESSION' else f['name'])
        raw = f['strength'] * f['reliability']
        if f['parent_only']:
            raw *= policy['parent_only_factor']
        groups[group] = max(groups.get(group, 0.), raw)
        weights[group] = max(weights.get(group, 0.), f['reliability'])
        anchor = (f['anchor_kind'] and not f['hot'] and f['strength'] >= policy['minimum_anchor_strength'])
        if anchor:
            q = f['strength'] * f['reliability'] if f['anchor_kind'] == 'attested_relation' else (
                policy['anchor_reliability'] * (policy['anchor_rarity_floor'] +
                (1-policy['anchor_rarity_floor']) * f['strength']))
            anchors[f['anchor_kind']] = max(anchors.get(f['anchor_kind'], 0.), q)
        audit.append(dict(feature=f['name'], independence_group=group, raw_support=f['strength'],
                          normalized_support=raw, reliability=f['reliability'], parent_only=f['parent_only']))
    temporal = policy['time_floor'] + (1-policy['time_floor']) * time
    mass = 1-math.prod(1-v for _, v in sorted(groups.items()))
    # A exposes observed-zero confidence loss; no missing/unobservable denominator.
    denom = math.fsum(weights.values()) + policy['observed_zero_weight'] * neutral
    quality = math.fsum(groups.values()) / denom if denom else 0.
    if model == 'A':
        positive = quality * mass * temporal
    elif model == 'B':
        # Session/network/asset/resource are correlated views of one observation.
        collapsed = dict(groups)
        if 'session' in collapsed:
            collapsed['session'] = max(collapsed['session'], collapsed.pop('context', 0.))
        positive = (1-math.prod(1-v for _, v in sorted(collapsed.items()))) * temporal
    else:
        # Anchor is an alternative pathway, not another noisy-OR component.
        anchor_value = max(anchors.values(), default=0.)
        context = max(groups.get('context', 0.), groups.get('identity', 0.))
        contextual = policy['context_floor'] + (1-policy['context_floor']) * context
        positive = max(min(mass, policy['weak_ceiling']), anchor_value * contextual) * temporal
    raw = positive - environment['conflict_penalty'] - environment['duplicate_penalty']
    final = min(1., max(0., raw))
    # Parent-only evidence must never become an exact process anchor.
    strong = bool(anchors) or sum(v > 0 for v in groups.values()) >= 2
    post_ceiling = final if strong else min(final, policy['weak_ceiling'])
    gate = environment['valid'] and environment['gate']['passed'] and bool(groups)
    return dict(score=post_ceiling if gate else 0., pre_ceiling_score=final,
                post_ceiling_score=post_ceiling, raw_total=raw, positive=positive,
                groups=groups, mass=mass, quality=quality, temporal_factor=temporal,
                anchor=bool(anchors), anchor_types=sorted(anchors), anchor_support=anchors,
                contradiction=environment['conflict_penalty'] > 0,
                conflict_penalty=environment['conflict_penalty'],
                duplicate_penalty=environment['duplicate_penalty'], gate=bool(gate),
                decomposition=audit)


def admits(result, threshold, policy_name, config):
    if not result['gate']:
        return False
    required = threshold
    if policy_name == 'evidence_class' and not result['anchor']:
        required += config['context_threshold_increment']
    elif policy_name == 'strong_anchor' and not result['anchor']:
        return False
    elif policy_name == 'contradiction_gate' and result['contradiction']:
        return False
    elif policy_name == 'mass_floor' and result['mass'] < config['mass_floor']:
        return False
    elif policy_name not in {'global', 'evidence_class', 'strong_anchor', 'contradiction_gate', 'mass_floor'}:
        raise ValueError('unknown_policy')
    return result['score'] >= required

"""Offline V5.1 research projection and identity-blind arithmetic.

No production registration. Strings, IDs and source names never enter score().
Compatibility is an evidence assessment, not a label or incident-membership veto.
"""
import json
import math
from datetime import datetime

SUPPORTED, UNKNOWN, CONTRADICTED = 'SUPPORTED', 'UNKNOWN', 'CONTRADICTED'
DIMENSIONS = ('scope', 'lifecycle', 'role', 'task', 'temporal')


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def resolve(raw, path):
    try:
        for part in path.strip('/').split('/'):
            raw = raw[part.replace('~1', '/').replace('~0', '~')]
        return raw if raw is not None and raw != '' else None
    except (KeyError, TypeError):
        return None


def observed(alert, paths):
    values = [(p, resolve(alert['raw_alert'], p)) for p in paths]
    values = [(p, v) for p, v in values if v is not None]
    # Conflicting aliases are not silently resolved by priority.
    if values and any(v != values[0][1] for _, v in values):
        return None, []
    return (values[0][1], [dict(alert_id=alert['alert_id'], pointer=p, side='shared')
                          for p, _ in values]) if values else (None, [])


def compare(a, b):
    return UNKNOWN if a is None or b is None else SUPPORTED if a == b else CONTRADICTED


def compatibility(a, b, binding, policy):
    """Observe scope/epoch/task boundaries; absence never means disagreement."""
    values, refs = {}, []
    for key, paths in policy['evidence_paths'].items():
        left, lr = observed(a, paths); right, rr = observed(b, paths)
        values[key] = (left, right); refs.extend(lr + rr)
    states = {k: UNKNOWN for k in DIMENSIONS}
    states['scope'] = compare(*values['scope'])
    if binding['type'] == 'PROCESS':
        if states['scope'] == UNKNOWN:
            states['scope'] = SUPPORTED  # exact scoped host+pid+start_time, checked by projector
        states['lifecycle'] = SUPPORTED
        states['role'] = SUPPORTED if not binding.get('parent_only') else UNKNOWN
        states['temporal'] = (SUPPORTED if all(timestamp(x['timestamp']) >=
            timestamp(binding['instance_start']) for x in (a, b)) else CONTRADICTED)
        kind = 'process'
    else:
        try:
            scope = json.loads(binding['scope']); kind = scope.get('identity_kind', 'untyped')
            namespace = scope.get('namespace')
            if states['scope'] == UNKNOWN and namespace and kind in policy['task_kinds'] + ['auth_session']:
                states['scope'] = SUPPORTED
        except (ValueError, TypeError, AttributeError):
            kind = 'untyped'
    if any(v is not None for v in values['epoch']):
        states['lifecycle'] = compare(*values['epoch'])
    starts, ends = values['start'], values['end']
    if all(v is not None for v in (*starts, *ends)):
        try:
            valid = all(timestamp(s) <= timestamp(x['timestamp']) <= timestamp(e)
                        for x, s, e in zip((a, b), starts, ends))
            overlap = max(map(timestamp, starts)) <= min(map(timestamp, ends))
            states['temporal'] = SUPPORTED if valid and overlap else CONTRADICTED
            if states['lifecycle'] == UNKNOWN:
                states['lifecycle'] = SUPPORTED if starts[0] == starts[1] and ends[0] == ends[1] else UNKNOWN
        except (ValueError, TypeError):
            pass  # malformed evidence cannot be upgraded to support
    states['task'] = compare(*values['task'])
    if states['task'] == UNKNOWN:
        states['task'] = compare(*values['request'])
    if states['task'] == UNKNOWN and binding['type'] == 'SESSION':
        states['task'] = compare(*values['transaction'])
    left, right = values['role']
    if left in policy['task_roles'] and right in policy['task_roles']:
        states['role'] = SUPPORTED
    elif left is not None and right is not None and (left in policy['context_roles'] or right in policy['context_roles']):
        # Container role is compatible as a context; it is never proof of a task.
        states['role'] = SUPPORTED
    known_context = binding['type'] == 'PROCESS' or kind in policy['context_kinds']
    taxonomy = ('TASK_SCOPED_ANCHOR' if all(s == SUPPORTED for s in states.values()) else
                'CONTEXT_ANCHOR' if known_context else 'IDENTITY_ONLY')
    return dict(taxonomy=taxonomy, dimensions=states, evidence_refs=sorted(refs,
                key=lambda r: (r['alert_id'], r['pointer'])), identity_kind=kind)


def project(environment, bindings, a, b, entities, behavior, policy):
    """Separates bound evidence from numeric score input. Never reads a file."""
    env = {**environment, 'behavior': behavior, 'anchors': []}
    bound = []
    for f in environment['features']:
        if f['state'] != 'OBSERVED_SUPPORT' or f['hot'] or not (f.get('anchor_kind') or f['name'] == 'entity.SESSION'):
            continue
        if f['anchor_kind'] == 'attested_relation':
            item = dict(feature=f['name'], taxonomy='DIRECT_RELATION_ANCHOR',
                        dimensions={k: SUPPORTED for k in DIMENSIONS}, evidence_refs=[])
            item['identity_strength'] = f['strength']; item['reliability'] = f['reliability']
            env['anchors'].append(item); bound.append(item)
            continue
        kind = 'SESSION' if f['name'] == 'entity.SESSION' else 'PROCESS'
        for binding in bindings:
            if binding['type'] != kind or binding.get('parent_only'):
                continue
            binding = dict(binding)
            if kind == 'PROCESS':
                try:
                    value = json.loads(entities[binding['entity_id']]['value'])
                    if not (value.get('host') and value.get('pid') is not None and value.get('start_time')):
                        continue
                    binding['instance_start'] = value['start_time']
                except (KeyError, ValueError, TypeError, AttributeError):
                    continue
            item = compatibility(a, b, binding, policy)
            item.update(feature=f['name'], identity_strength=policy['identity_rarity_floor'] +
                (1-policy['identity_rarity_floor'])*f['strength'], reliability=policy['identity_reliability'])
            bound.append({**item, 'binding': binding})
            env['anchors'].append({k: v for k, v in item.items() if k not in {'evidence_refs', 'identity_kind'}})
    return env, bound


def score(env, policy):
    """Three alternative proof paths; no identity-equality escape hatch."""
    anchors = []
    for a in sorted(env['anchors'], key=lambda a: (a['feature'], a['taxonomy'], str(a['dimensions']))):
        if set(a['dimensions']) != set(DIMENSIONS) or any(v not in {SUPPORTED, UNKNOWN, CONTRADICTED}
                                                         for v in a['dimensions'].values()):
            raise ValueError('invalid_compatibility_dimension')
        factors = {k: 1. if v == SUPPORTED else 0. if v == CONTRADICTED else
                   policy['unknown_compatibility'] for k, v in a['dimensions'].items()}
        compatibility_value = math.prod(factors.values())
        effective = a['identity_strength'] * a['reliability'] * compatibility_value
        anchors.append(dict(feature=a['feature'], taxonomy=a['taxonomy'], dimensions=a['dimensions'],
            factors=factors, identity_strength=a['identity_strength'], reliability=a['reliability'],
            semantic_compatibility=compatibility_value, effective_support=effective))
    groups = {}; time = 0.
    for f in sorted(env['features'], key=lambda f: f['name']):
        if f['state'] != 'OBSERVED_SUPPORT': continue
        if f['family'] == 'time': time = max(time, f['strength'])
        if f['family'] not in {'entity', 'relation'} or f['role'] == 'direct': continue
        kind = f['name'].removeprefix('entity.')
        group = ('identity' if kind == 'ACCOUNT' else 'execution' if kind in {'FILE', 'COMMAND'} else 'context')
        value = f['strength'] * f['reliability']
        if kind in {'SESSION', 'PROCESS'}:
            value = max((a['effective_support'] for a in anchors if a['feature'] == f['name']), default=0.)
        if f.get('parent_only'): value *= policy['parent_only_factor']
        groups[group] = max(groups.get(group, 0.), value)
    mass = 1-math.prod(1-v for _, v in sorted(groups.items()))
    direct = max((a['effective_support'] for a in anchors if a['taxonomy'] == 'DIRECT_RELATION_ANCHOR'), default=0.)
    contextual = max(groups.get('context', 0.), groups.get('identity', 0.), groups.get('execution', 0.))
    # An anchor's own identity is excluded from its contextual corroboration.
    non_anchor = [f['strength']*f['reliability'] for f in env['features']
                  if f['state'] == 'OBSERVED_SUPPORT' and f['family'] == 'entity'
                  and f['name'] not in {'entity.SESSION', 'entity.PROCESS'}
                  and not f.get('anchor_kind') and not f['hot']]
    corroboration = max(non_anchor, default=0.)
    pair_context = 1-(1-corroboration)*(1-env['behavior']) if corroboration else 0.
    task = max((a['effective_support'] * pair_context for a in anchors
                if a['taxonomy'] == 'TASK_SCOPED_ANCHOR'), default=0.)
    contradictions = [a for a in anchors if CONTRADICTED in a['dimensions'].values()]
    # Contradictory local boundaries remove a shared-context explanation. A verified
    # cross-boundary relation can still prevail via the separate direct path.
    weak = 0. if contradictions else mass * env['behavior']
    weak_unlocked = (sum(v > 0 for v in groups.values()) >= policy['minimum_weak_groups']
                     and env['behavior'] >= policy['behavior_minimum'])
    if not weak_unlocked: weak = min(weak, policy['weak_ceiling'])
    temporal = policy['time_floor'] + (1-policy['time_floor'])*time
    positive = max(direct, task, weak) * temporal
    raw = positive - env['conflict_penalty'] - env['duplicate_penalty']
    gate = (env['valid'] and env['gate']['passed'] and not env['gate']['hard_contradiction']
            and not env['gate']['duplicate_observation'] and bool(groups or direct))
    return dict(score=min(1., max(0., raw)) if gate else 0., gate=bool(gate), groups=groups,
        mass=mass, anchors=anchors, direct_support=direct, task_support=task,
        contextual_support=contextual, independent_corroboration=corroboration,
        pair_contextual_support=pair_context,
        weak_support=weak, weak_unlocked=weak_unlocked, behavior_support=env['behavior'],
        temporal_factor=temporal, positive_support=positive, raw_total=raw,
        conflict_penalty=env['conflict_penalty'], duplicate_penalty=env['duplicate_penalty'])

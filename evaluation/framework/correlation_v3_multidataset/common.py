"""Deterministic statistics, source inventory and immutable recipe."""

from collections import Counter, defaultdict
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import sys

from app.models.base import resolve_pointer
from app.services.datasets import load_dataset, read_registry
from app.services.storage import atomic_json, file_digest, restore_config
from app.utils.stable_id import content_digest


FIELDS = ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'host', 'account', 'session',
          'process', 'parent_process', 'file', 'command', 'domain', 'url', 'flow_id',
          'rule_id', 'category', 'signature', 'severity')
BOUNDS = (0, .1, .2, .3, .4, .5, .6, .65, .7, .8, .9, 1)
FAMILIES = ('ENTITY_IDENTITY', 'NETWORK_FLOW', 'TEMPORAL', 'HOST_CONTEXT',
            'ACCOUNT_CONTEXT', 'PROCESS_CONTEXT', 'RESOURCE_CONTEXT',
            'BEHAVIOR_SEMANTIC', 'RULE_METADATA', 'SOURCE_CONTEXT')


def ratio(n, d):
    return n / d if d else None


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write(path, value):
    # Internal production rankings are tuples, not domain model fields. JSON
    # arrays preserve their ordering in evaluation artifacts without changing
    # the objects or values supplied to any production function.
    atomic_json(Path(path), json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False)))


def bucket(score):
    for lo, hi in zip(BOUNDS, BOUNDS[1:]):
        if lo <= score < hi or score == 1 and hi == 1:
            return f'[{lo:.2f},{hi:.2f}' + (']' if hi == 1 else ')')
    raise ValueError('score_outside_unit_interval')


def distribution(values):
    ordered = sorted(values)
    def percentile(q):
        if not ordered:
            return None
        p = (len(ordered)-1)*q
        lo, hi = math.floor(p), math.ceil(p)
        return ordered[lo] + (ordered[hi]-ordered[lo])*(p-lo)
    result = {'count': len(ordered), 'min': min(ordered) if ordered else None,
              'max': max(ordered) if ordered else None,
              'mean': math.fsum(ordered)/len(ordered) if ordered else None,
              **{f'P{p}': percentile(p/100) for p in (25, 50, 75, 90, 95, 99)}}
    counts = Counter(bucket(v) for v in ordered)
    result['buckets'] = {bucket(lo): counts[bucket(lo)] for lo in BOUNDS[:-1]}
    result['status'] = 'available' if ordered else 'not_applicable'
    return result


def source(alert):
    return alert.source_type.value if hasattr(alert, 'source_type') else alert['source_type']


def pair_source(a, b):
    return ' ↔ '.join(sorted((source(a), source(b))))


def present(alert, field, config):
    if field == 'flow_id':
        pointers = config.algorithm.duplicate.observation.event_pointers.get(source(alert), {}).get('flow_id', [])
        for pointer in pointers:
            try:
                if resolve_pointer(alert.raw_alert, pointer) not in (None, ''):
                    return True
            except ValueError:
                pass
        return False
    value = getattr(alert, field)
    return value is not None and value != '' and getattr(value, 'value', value) != 'unknown'


def field_coverage(alerts, config):
    counts, populations = defaultdict(Counter), Counter()
    for alert in alerts:
        populations[source(alert)] += 1
        for field in FIELDS:
            counts[source(alert)][field] += int(present(alert, field, config))
    n = sum(populations.values())
    return {'denominator': 'unique CanonicalAlert; unknown category/severity are uncovered',
        'flow_id_scope': 'raw alert fields at frozen observation pointers; CanonicalAlert has no FLOW entity or flow_id field',
        'field_presence_rate': {f: ratio(sum(c[f] for c in counts.values()), n) for f in FIELDS},
        'field_presence_count': {f: sum(c[f] for c in counts.values()) for f in FIELDS},
        'field_presence_rate_by_source': {s: {f: ratio(counts[s][f], d) for f in FIELDS}
                                          for s, d in sorted(populations.items())},
        'source_denominators': dict(sorted(populations.items()))}


def freeze_recipe(root):
    """One algorithm AND source snapshot for every isolated scene invocation.

    All declared namespaces/timezones are included without aliasing identities.
    Unused source declarations do not contribute any alerts to an invocation.
    """
    registry = read_registry(root)
    datasets = {s: load_dataset(root, scene_id=s, config_version='v3')
                for s in sorted(registry.scenes) if registry.scenes[s].enabled}
    first = next(iter(datasets.values())).config.snapshot
    timezones, sources = {}, {}
    for loaded in datasets.values():
        snapshot = loaded.config.snapshot
        times = snapshot['normalization'].pop('source_timezones')
        reference = dict(first)
        reference['normalization'] = dict(first['normalization'])
        reference['normalization'].pop('source_timezones', None)
        if snapshot != reference:
            raise ValueError('algorithm_or_mapping_differs_between_scenes')
        timezones.update(times)
        sources.update({k: v[1] for k, v in loaded.sources.items()})
    first['normalization']['source_timezones'] = dict(sorted(timezones.items()))
    config = restore_config(first)
    snapshot = {'algorithm': config.snapshot, 'sources': {k: v.snapshot() for k, v in sorted(sources.items())}}
    from app.correlation.edges import correlation_version
    recipe = {'algorithm_version': correlation_version(config), 'config_hash': content_digest(snapshot),
        'algorithm_config_hash': config.config_hash, 'mapping_digest': config.mapping_digest,
        'config_snapshot': snapshot, 'threshold': config.algorithm.score.correlation_threshold,
        'scene_ids': sorted(datasets), 'ground_truth_used_by_production': False,
        'isolation': 'each invocation receives alerts from exactly one scene; source declarations alone contain no alert evidence',
        'deployment_note': 'union of existing namespace/timezone declarations only; no identity aliases or new independence claims'}
    return datasets, config, sources, recipe


def discover(root, datasets):
    base = Path(root)/'data/ait_ads'
    rows = []
    for directory in sorted(p for p in base.iterdir() if p.is_dir()):
        loaded = datasets.get(directory.name)
        inputs = [] if loaded is None else loaded.inputs
        rows.append({'dataset': directory.name, 'registered': loaded is not None,
            'status': 'unregistered_no_namespace_or_profile' if loaded is None else
                      'missing_raw_data' if loaded.missing_files else 'files_present_unvalidated',
            'raw_files_discovered': [p.relative_to(root).as_posix() for p in sorted((directory/'raw').glob('*.json*'))],
            'inputs': [{**item, 'exists': (Path(root)/item['path']).is_file(),
                'bytes': (Path(root)/item['path']).stat().st_size if (Path(root)/item['path']).is_file() else None}
                for item in inputs],
            'source_settings': {} if loaded is None else {k: v[1].snapshot() for k, v in loaded.sources.items()},
            'version_readiness': 'accepted AIT-ADS v1 format profile; generator software version remains explicitly unknown'})
    return rows


def capture_integrity(root):
    root = Path(root)
    paths = set()
    for directory in ('backend/app', 'configs', 'docs', 'data/ait_ads', 'data/processed', 'outputs/analyses'):
        paths.update(p for p in (root/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for directory in ('correlation_v3', 'incremental_correlation'):
        paths.update(p for p in (root/'outputs'/directory).rglob('*') if p.is_file())
    paths.add(root/'AGENTS.md')
    return {p.relative_to(root).as_posix(): file_digest(p) for p in sorted(paths)}


@contextmanager
def truth_tripwire(root):
    """Runtime open tripwire active only while deterministic production runs.

    Evaluation modules are loaded before entry. No label reader is called until
    every attempted production invocation has ended and its result is frozen.
    """
    active = [True]
    root = Path(root).resolve()
    def audit(event, args):
        if event == 'open' and active[0] and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).resolve()
            if path.is_relative_to(root/'evaluation') or path.name.lower() in {
                'labels.csv', 'attacks.log', 'gold_chain.json', 'ground_truth.json'}:
                raise RuntimeError('production_ground_truth_access_blocked:'+str(path))
    sys.addaudithook(audit)
    try:
        yield
    finally:
        active[0] = False

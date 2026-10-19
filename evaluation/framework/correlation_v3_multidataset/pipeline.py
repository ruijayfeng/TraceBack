"""Isolated calls to the frozen production modules, without label access."""

from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import struct
import sys
import time
from types import SimpleNamespace

from app.adapters import AMinerAdapter, WazuhAdapter
from app.chains.assembly import run_reconstruction
from app.correlation.edges import peak_memory_mb, run_correlation
from app.correlation.index import AlertIndex
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.incidents.triage import triage_singletons
from app.models import CanonicalAlert
from app.services.storage import file_digest
from app.utils.stable_id import content_digest

from .common import FIELDS, field_coverage, freeze_recipe, present, ratio, read_json, source, truth_tripwire, write
from .observer import FrozenBudgetBlocked, Observer


class IndexResourceBlocked(RuntimeError):
    pass


class FrozenPipelineIncomplete(RuntimeError):
    pass


def index_storage_lower_bound(alerts, groups):
    """CPython lower bound for the EXISTING TemporalPosting.bits allocation.

    Each full-population global/source/sensor/entity posting materializes an
    independent ``1 << global_representative_position`` integer per member.
    Measure only those integers and list pointers; exclude all models, other
    postings metadata, block masks, candidate bitsets and scorer/index copies.
    This is an allocation proof, not a sampling/algorithm limit.
    """
    if sys.implementation.name != 'cpython':
        return {'status': 'unavailable_non_cpython'}
    owner = {a.alert_id: a.alert_id for a in alerts}
    for group in groups:
        owner.update({a: group.representative_alert_id for a in group.alert_ids})
    positions = {r: p for p, r in enumerate(sorted(set(owner.values())))}
    base = sys.getsizeof(1)-sys.int_info.sizeof_digit
    total, entries = 0, 0
    for alert in alerts:
        position = positions[owner[alert.alert_id]]
        count = 2+int(alert.sensor is not None)+len(alert.entity_ids)
        # Small cached integers could share storage; omit them conservatively.
        if position > 8:
            bytes_per = base+sys.int_info.sizeof_digit*(position//sys.int_info.bits_per_digit+1)
            total += count*(bytes_per+struct.calcsize('P'))
            entries += count
    return {'status': 'exact_cpython_allocation_lower_bound', 'bytes': total, 'MiB': total/(1024**2),
        'materialized_integer_entries_excluding_small_cache': entries, 'representative_count': len(positions),
        'reference': 'backend/app/correlation/index.py:TemporalPosting.__init__, AlertIndex.postings',
        'formula': 'sum over canonical members (2 + sensor_present + entity_count) * (int_header + digit_size * (position//bits_per_digit + 1) + pointer_size)',
        'exclusions': 'models, dictionaries, posting metadata, block masks, candidate audit, simultaneous index/scorer copies'}


def available_commit_mb():
    if sys.platform != 'win32':
        return None
    import ctypes
    class Status(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
            *[(name, ctypes.c_ulonglong) for name in ('total_physical', 'available_physical', 'total_pagefile',
                'available_pagefile', 'total_virtual', 'available_virtual', 'extended_virtual')]]
    status = Status()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return status.available_pagefile/(1024**2)


def population_view(alerts, groups, entities):
    """Lightweight EVALUATION/triage view, no retrieval/candidate operations.

    The formal correlation and reconstruction modules still construct their
    own unmodified AlertIndex. This observer does not need a third dense index
    just to count df, source coverage, or call the existing singleton triage.
    """
    by_id = {a.alert_id: a for a in alerts}
    owner = {a: a for a in by_id}
    for group in groups:
        owner.update({a: group.representative_alert_id for a in group.alert_ids})
    members = defaultdict(list)
    for aid, rep in owner.items():
        members[rep].append(aid)
    grouped = {r: tuple(sorted(ids)) for r, ids in sorted(members.items())}
    return SimpleNamespace(alerts=by_id, owner=owner, groups=grouped, N=len(grouped),
        representatives=tuple(grouped), entities={e.entity_id: e for e in entities},
        df={e.entity_id: len({owner[a] for a in e.alert_ids}) for e in entities})


def progress(scene, stage, **values):
    print(json.dumps({'dataset': scene, 'stage': stage, **values}, ensure_ascii=False), flush=True)


def raw_records(path):
    """Same envelopes as production ingress; parser failures are quarantined."""
    with Path(path).open(encoding='utf-8-sig') as handle:
        first = handle.read(1)
        handle.seek(0)
        if first == '[':
            yield from json.load(handle)
        else:
            for line in handle:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except ValueError:
                        yield line


def scan_scene(root, loaded, config, destination):
    """Validate EVERY raw record and measure unique canonical field coverage.

    Small adapter batches are used only for ingress and byte-preserving storage.
    Dedupe/candidates/scoring never run on these batches: full scenario population
    is restored in a separate worker before any such decision.
    """
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    seen, rows = set(), []
    counts, fields, source_counts = Counter(), defaultdict(Counter), Counter()
    rejected, imports = Counter(), []
    stamp_min, stamp_max = None, None
    with gzip.open(destination/'canonical_ingress.jsonl.gz', 'wt', encoding='utf-8', compresslevel=1) as output:
        for item in loaded.inputs:
            path = Path(root)/item['path']
            before = file_digest(path)
            adapter = (AMinerAdapter if item['source'] == 'aminer' else WazuhAdapter)(config, loaded.sources[item['source_ref']][1])
            file_count, file_accepted, buffer = 0, 0, []
            def consume(buffer):
                nonlocal file_count, file_accepted, stamp_min, stamp_max
                batch = adapter.batch(buffer)
                file_count += batch.input_count
                file_accepted += batch.accepted_count
                counts['raw_alert_count'] += batch.input_count
                counts['accepted_records'] += batch.accepted_count
                rejected.update(batch.rejection_reasons)
                for alert in batch.alerts:
                    if alert.alert_id in seen:
                        continue
                    seen.add(alert.alert_id)
                    source_counts[source(alert)] += 1
                    for field in FIELDS:
                        fields[source(alert)][field] += int(present(alert, field, config))
                    stamp_min = min(stamp_min, alert.timestamp) if stamp_min else alert.timestamp
                    stamp_max = max(stamp_max, alert.timestamp) if stamp_max else alert.timestamp
                    output.write(alert.canonical_json()+'\n')
                if file_count % 10240 == 0:
                    progress(loaded.scene_id, 'full_adapter_validation', source=item['source'],
                             records=file_count, elapsed_seconds=round(time.perf_counter()-started, 1))
            for raw in raw_records(path):
                buffer.append(raw)
                if len(buffer) == 256:
                    consume(buffer)
                    buffer.clear()
            if buffer:
                consume(buffer)
            if file_digest(path) != before:
                raise ValueError('raw_input_changed_during_preflight')
            imports.append({**item, 'sha256': before, 'record_count': file_count,
                'accepted_records': file_accepted, 'rejected_records': file_count-file_accepted})
    n = len(seen)
    field_report = {'denominator': 'unique CanonicalAlert; unknown category/severity are uncovered',
        'flow_id_scope': 'frozen raw observation pointers; not a schema or entity extension',
        'field_presence_rate': {f: ratio(sum(c[f] for c in fields.values()), n) for f in FIELDS},
        'field_presence_count': {f: sum(c[f] for c in fields.values()) for f in FIELDS},
        'field_presence_rate_by_source': {s: {f: ratio(fields[s][f], d) for f in FIELDS} for s, d in sorted(source_counts.items())},
        'source_denominators': dict(sorted(source_counts.items()))}
    result = {'dataset': loaded.scene_id, 'status': 'ready' if not rejected and n else 'invalid_canonical_input',
        'raw_alert_count': counts['raw_alert_count'], 'canonical_alert_count': n,
        'accepted_records': counts['accepted_records'], 'duplicate_import_count': counts['accepted_records']-n,
        'rejected_count': sum(rejected.values()), 'rejection_reasons': dict(rejected),
        'inputs': imports, 'source_alert_count': dict(source_counts), 'field_coverage': field_report,
        'min_timestamp': stamp_min,
        'max_timestamp': stamp_max,
        'full_adapter_validation': True, 'elapsed_seconds': time.perf_counter()-started,
        'canonical_ingress_sha256': file_digest(destination/'canonical_ingress.jsonl.gz')}
    write(destination/'preflight.json', result)
    progress(loaded.scene_id, 'preflight_completed', records=counts['raw_alert_count'], canonical=n, rejected=sum(rejected.values()))
    return result


def entity_statistics(index, config):
    frequencies, observations, covered = defaultdict(list), Counter(), defaultdict(set)
    cross_sources, high, once, reuse = [], [], [], []
    for entity in index.entities.values():
        kind = entity.type.value
        df = index.df[entity.entity_id]
        frequencies[kind].append(df)
        observations[kind] += sum(sum(o.entity_id == entity.entity_id for o in index.alerts[a].entity_occurrences)
                                  for a in entity.alert_ids)
        covered[kind].update(index.owner[a] for a in entity.alert_ids)
        srcs = sorted({source(index.alerts[a]) for a in entity.alert_ids})
        row = {'entity_id': entity.entity_id, 'type': kind, 'scope': entity.scope, 'value': entity.value,
               'representative_df': df, 'raw_alert_df': len(entity.alert_ids), 'sources': srcs}
        if len(srcs) > 1:
            cross_sources.append(row)
        if df == 1:
            once.append(row)
        if df >= config.algorithm.candidate.hot_entity_min_count and df/index.N >= config.algorithm.candidate.hot_entity_ratio:
            high.append(row)
        if df >= 2:
            reuse.append(row)
    type_rows = {kind: {'unique_count': len(values), 'observation_count': observations[kind],
        'representative_coverage_count': len(covered[kind]), 'representative_coverage': ratio(len(covered[kind]), index.N),
        'frequency_distribution': {str(k): v for k, v in sorted(Counter(values).items())},
        'single_occurrence_entities': sum(v == 1 for v in values), 'reused_entity_count': sum(v >= 2 for v in values)}
        for kind, values in sorted(frequencies.items())}
    from app.models import EntityType
    for kind in EntityType:
        type_rows.setdefault(kind.value, {'unique_count': 0, 'observation_count': 0, 'representative_coverage_count': 0,
            'representative_coverage': 0, 'frequency_distribution': {}, 'single_occurrence_entities': 0, 'reused_entity_count': 0})
    type_rows['FLOW'] = {'status': 'not_applicable', 'reason': 'frozen schema has nine entity types; flow is raw observation identity'}
    return {'population': index.N, 'df_unit': 'dedupe representative', 'types': type_rows,
        'high_frequency_entities': sorted(high, key=lambda r: (-r['representative_df'], r['entity_id'])),
        'cross_source_entities': sorted(cross_sources, key=lambda r: r['entity_id']),
        'single_occurrence_count': len(once), 'low_frequency_definition': 'df in [2,5]',
        'low_frequency_count': sum(2 <= r['representative_df'] <= 5 for r in reuse),
        'reused_entity_count': len(reuse),
        'entity_reuse_observations': sum(r['representative_df'] for r in reuse),
        'cross_alert_entity_reuse_ratio': ratio(sum(r['representative_df'] for r in reuse), sum(index.df.values())),
        'shared_entity_pair_exposures': sum(r['representative_df']*(r['representative_df']-1)//2 for r in reuse),
        'pair_exposure_note': 'entity-wise sum; overlaps and time eligibility prevent interpreting as unique candidate pairs'}


def write_models(path, models):
    import hashlib
    digest = hashlib.sha256()
    with gzip.open(path, 'wb', compresslevel=1) as handle:
        for model in models:
            row = (model.canonical_json()+'\n').encode('utf-8')
            handle.write(row)
            digest.update(row)
    return digest.hexdigest()


def run_scene(root, scene, destination):
    datasets, config, settings, recipe = freeze_recipe(root)
    destination = Path(destination)
    ingress = read_json(destination/'preflight.json')
    if ingress['status'] != 'ready':
        raise ValueError('data_readiness_gate_not_met')
    if file_digest(destination/'canonical_ingress.jsonl.gz') != ingress['canonical_ingress_sha256']:
        raise ValueError('canonical_ingress_changed')
    for item in ingress['inputs']:
        if file_digest(Path(root)/item['path']) != item['sha256']:
            raise ValueError('raw_input_changed_after_preflight')
    result = {'dataset': scene, 'status': 'running', 'config_hash': recipe['config_hash'],
        'mapping_digest': recipe['mapping_digest'], 'algorithm_version': recipe['algorithm_version'],
        'counts': {'raw_alert_count': ingress['raw_alert_count'], 'canonical_alert_count': ingress['canonical_alert_count']},
        'field_coverage': ingress['field_coverage'], 'source_alert_count': ingress['source_alert_count'],
        'stages': {}, 'ground_truth_used': False, 'ai_used': False}
    started = time.perf_counter()
    observer = None
    def checkpoint(stage, **extra):
        result['active_stage'] = stage
        result.update(extra)
        result['peak_memory_mb'] = peak_memory_mb()
        write(destination/'pipeline_checkpoint.json', result)
        progress(scene, stage, **extra.get('counts', {}), peak_memory_mb=result['peak_memory_mb'])
    try:
        with truth_tripwire(root):
            checkpoint('restore_full_canonical_population')
            with gzip.open(destination/'canonical_ingress.jsonl.gz', 'rt', encoding='utf-8') as handle:
                alerts = sorted((CanonicalAlert.model_validate_json(line) for line in handle), key=lambda a: a.alert_id)
            if len(alerts) != ingress['canonical_alert_count'] or any(a.source_namespace not in datasets[scene].sources for a in alerts):
                raise ValueError('scenario_population_isolation_failed')
            step = time.perf_counter()
            checkpoint('dedupe')
            dedupe = deduplicate(alerts, config, settings)
            result['stages']['dedupe'] = {'seconds': time.perf_counter()-step, 'complete': dedupe.is_complete}
            result['counts'].update(dedupe_group_count=len(dedupe.groups),
                representative_count=len(alerts)-sum(len(g.alert_ids)-1 for g in dedupe.groups))
            step = time.perf_counter()
            checkpoint('entity_extraction')
            extracted = extract_entities(alerts, settings)
            alerts, entities = extracted.alerts, extracted.entities
            result['stages']['entity_extraction'] = {'seconds': time.perf_counter()-step}
            result['counts']['entity_count'] = len(entities)
            index = population_view(alerts, dedupe.groups, entities)
            result['entity_distribution'] = entity_statistics(index, config)
            result['source_entity_coverage'] = {src: ratio(sum(bool(a.entity_ids) for a in alerts if source(a) == src), n)
                                               for src, n in ingress['source_alert_count'].items()}
            bound = index_storage_lower_bound(alerts, dedupe.groups)
            bound['available_commit_mb_at_probe'] = available_commit_mb()
            result['index_resource_probe'] = bound
            checkpoint('entity_index')
            if bound.get('MiB') is not None and bound['available_commit_mb_at_probe'] is not None and bound['MiB'] > bound['available_commit_mb_at_probe']-512:
                raise IndexResourceBlocked('full_population_index_bit_storage_exceeds_available_commit')
            result['counts'].update(representative_count=index.N, dedupe_group_count=len(dedupe.groups), entity_count=len(entities))
            result['source_representative_count'] = dict(Counter(source(index.alerts[r]) for r in index.representatives))
            # Groups can span products; report both representative owner and
            # source participation, rather than dropping non-owner wrappers.
            result['source_representative_participation'] = dict(Counter(
                src for rep in index.representatives for src in {source(index.alerts[m]) for m in index.groups[rep]}))
            result['source_entity_coverage'] = {src: ratio(sum(bool(a.entity_ids) for a in alerts if source(a) == src), n)
                                                for src, n in ingress['source_alert_count'].items()}
            result['dataset_digest'] = content_digest([[a.alert_id, a.raw_fingerprint] for a in alerts])
            checkpoint('candidate_generation')
            with (destination/'pipeline_diagnostics.jsonl').open('w', encoding='utf-8') as diagnostic_file:
                observer = Observer(destination, diagnostic_file, config)
                correlation = run_correlation(alerts, dedupe.groups, entities, config, settings,
                    diagnostic_sink=observer, progress=lambda row: progress(scene, row['stage'], **{k: v for k, v in row.items() if k != 'stage'}))
                if correlation.record.config_hash != recipe['config_hash']:
                    raise ValueError('cross_dataset_config_hash_mismatch')
                if not correlation.record.is_complete:
                    result['production_record'] = correlation.record.model_dump(mode='json')
                    raise FrozenPipelineIncomplete(correlation.record.incomplete_reason or 'frozen_correlation_incomplete')
                result['candidate_stats'] = observer.candidate_summary
                result['counts'].update(candidate_pair_count=correlation.summary['admitted_candidate_count'],
                    scored_candidate_count=correlation.summary['scored_candidate_count'], correlation_edge_count=len(correlation.edges))
                checkpoint('incident_and_chain')
                reconstruction = run_reconstruction(alerts, dedupe.groups, entities, correlation.edges, config, settings,
                    upstream_record=correlation.record, diagnostic_sink=observer,
                    progress=lambda row: progress(scene, row['stage'], **{k: v for k, v in row.items() if k != 'stage'}))
                checkpoint('singleton_triage')
                reconstruction.incidents = triage_singletons(reconstruction.incidents, index, config, correlation.summary,
                    search_complete=reconstruction.record.is_complete and dedupe.is_complete)
                observer.close()
            observation = observer.finish_observation()
            result.update(observation)
            result['production_record'] = correlation.record.model_dump(mode='json')
            result['grounding'] = reconstruction.grounding.json_data()
            sizes = [len({index.owner[a] for a in i.alert_ids}) for i in reconstruction.incidents]
            result['counts'].update(incident_count=len(sizes), singleton_incident_count=sizes.count(1),
                multi_alert_incident_count=sum(v > 1 for v in sizes),
                raw_singleton_incident_count=sum(len(i.alert_ids) == 1 for i in reconstruction.incidents),
                chain_edge_count=sum(len(c.edges) for c in reconstruction.chains),
                high_risk_singleton_count=sum(i.single_alert_triage is not None and i.single_alert_triage.risk_level in {'high', 'critical'}
                                             for i in reconstruction.incidents))
            result['status'] = 'completed' if reconstruction.record.is_complete and dedupe.is_complete else 'incomplete'
            result['object_digests'] = {name: write_models(destination/(name+'.jsonl.gz'), models) for name, models in (
                ('alerts', alerts), ('dedupe_groups', dedupe.groups), ('entities', entities),
                ('correlation_edges', correlation.edges), ('incidents', reconstruction.incidents), ('attack_chains', reconstruction.chains))}
            result['correlation_summary'] = {k: v for k, v in correlation.summary.items() if k not in {
                'alert_correlation_diagnostics', 'accepted_samples', 'cross_source_samples', 'same_source_samples', 'highest_rejected_samples'}}
            write(destination/'frequency_snapshot.json', observer.index.frequency_snapshot())
            result['total_seconds'] = time.perf_counter()-started
            result['peak_memory_mb'] = peak_memory_mb()
            result['active_stage'] = 'frozen_production_complete'
            write(destination/'result.json', result)
            progress(scene, result['status'], **result['counts'])
            return result
    except FrozenBudgetBlocked as exc:
        result.update(status='blocked', blocked_stage='scoring', blocked_reason=str(exc),
            candidate_stats=observer.candidate_summary,
            limitation='frozen candidate budget omits admitted pairs; no partial formal graph or complete comparison is published')
        result['counts']['candidate_pair_count'] = observer.candidate_summary['admitted_candidate_count']
        result['counts']['scored_candidate_count'] = 0
    except FrozenPipelineIncomplete as exc:
        result.update(status='blocked', blocked_stage=result.get('active_stage'), blocked_reason=str(exc),
            limitation='production returned an explicitly incomplete record; unavailable full-population counts remain null')
    except IndexResourceBlocked as exc:
        result.update(status='blocked', blocked_stage='entity_index', blocked_reason=str(exc),
            limitation='existing index allocation lower bound exceeds host available commit; no input sampling or production representation change')
    except (MemoryError, OSError) as exc:
        result.update(status='blocked', blocked_stage=result.get('active_stage'), blocked_reason=type(exc).__name__+':'+str(exc))
    except Exception as exc:
        result.update(status='failed', blocked_stage=result.get('active_stage'), blocked_reason=type(exc).__name__+':'+str(exc))
        import traceback
        result['traceback'] = traceback.format_exc()
    result['total_seconds'] = time.perf_counter()-started
    write(destination/'result.json', result)
    progress(scene, result['status'], reason=result['blocked_reason'])
    return result

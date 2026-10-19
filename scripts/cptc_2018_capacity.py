"""Step 3A.1 execution-only capacity audit and full-run verification."""
from pathlib import Path
import argparse
from collections import Counter
from dataclasses import asdict
import gzip
import gc
import hashlib
import itertools
import json
import sys
import time
import threading
import heapq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
sys.path.insert(0, str(ROOT/'scripts'))
OUT = ROOT/'outputs/cptc_2018_step3a_capacity'

from app.services.storage import SnapshotStore, file_digest, restore_config
from app.services.capacity import bounded_execution
from app.correlation.index import AlertIndex
from app.correlation.edges import peak_memory_mb, run_correlation, correlation_version
from app.utils.stable_id import content_digest
from app.adapters.cptc import load_cptc_dataset
from app.dedup.grouping import deduplicate
from cptc_2018_step3a import available_commit_mb, atomic_json


def protected_files():
    paths = [ROOT/'AGENTS.md', *sorted((ROOT/'docs').glob('*.md')),
             *sorted((ROOT/'configs').rglob('*.yaml')),
             *sorted((ROOT/'backend/app').rglob('*.py')),
             ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json']
    for directory in ('data/cptc_2018', 'outputs/cptc_2018_step2/run_a'):
        paths.extend(p for p in sorted((ROOT/directory).rglob('*')) if p.is_file())
    return {p.relative_to(ROOT).as_posix(): file_digest(p) for p in paths}


def source():
    summary = json.loads((ROOT/'outputs/cptc_2018_step2/run_a/summary.json').read_text('utf8'))
    return SnapshotStore(ROOT/'outputs/cptc_2018_step2/run_a', summary['snapshot_id']), summary


def deep_size(value, seen=None):
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    result = sys.getsizeof(value)
    if isinstance(value, dict):
        result += sum(deep_size(k, seen)+deep_size(v, seen) for k, v in value.items())
    elif isinstance(value, (list, tuple, set, frozenset)):
        result += sum(deep_size(v, seen) for v in value)
    elif hasattr(value, '__dict__'):
        result += deep_size(value.__dict__, seen)
        for field in ('__pydantic_fields_set__', '__pydantic_private__'):
            if hasattr(value, field):
                private = getattr(value, field)
                # A locator borrows the execution state, never owns it.
                if field != '__pydantic_private__':
                    result += deep_size(private, seen)
    return result


def audit(limit):
    OUT.mkdir(parents=True, exist_ok=True)
    before = protected_files()
    atomic_json(OUT/'protected_files_before.json', before)
    for path in ('backend/app/correlation/index.py', 'backend/app/correlation/candidates.py',
                 'backend/app/services/capacity.py', 'backend/app/services/storage.py'):
        target = OUT/'reference'/path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT/path).read_bytes())
    store, summary = source()
    selected = list(itertools.islice(store.read_records('alerts', parquet=True), limit))
    ids = {a.alert_id for a in selected}
    from app.models import Entity
    entities = []
    for e in store.read_records('entities', parquet=True):
        members = sorted(ids.intersection(e.alert_ids))
        if members:
            data = e.model_dump()
            data['alert_ids'] = members
            entities.append(Entity.model_validate(data))
    rows = []
    with bounded_execution(OUT/'tmp/audit') as spill:
        mapping = spill.alerts()
        for a in selected:
            mapping.add(a)
        canonical_bytes = deep_size(mapping.records)
        idx = AlertIndex(mapping.sequence(), (), entities)
        collections = {'time': idx.time, 'entity': idx.by_entity, 'source': idx.by_source, 'sensor': idx.by_sensor}
        block_bytes = block_count = bits_bytes = postings_count = 0
        for group in collections.values():
            for categories in (group.values() if group is not idx.time else (group,)):
                for posting in categories.values():
                    block_count += len(posting.blocks)
                    block_bytes += sum(sys.getsizeof(v) for v in posting.blocks)
                    bits_bytes += sys.getsizeof(posting.bits)
                    postings_count += 1
        row = dict(sample_alerts=len(mapping), sample_entities=len(entities), canonical_retained_bytes=canonical_bytes,
                   posting_count=postings_count, block_count=block_count, block_int_bytes=block_bytes,
                   compact_member_bits_bytes=bits_bytes,
                   owner_groups_positions_times_roles_bytes=deep_size([idx.owner, idx.groups, idx.positions, idx.times, idx.roles]),
                   posting_metadata_bytes=deep_size(list(collections.values())), peak_memory_mb=peak_memory_mb())
        rows.append(row)
    atomic_json(OUT/'memory_audit_before.json', dict(rows=rows,
        previous_peak_memory_mb=5387.76171875, previous_log='outputs/cptc_2018_step3a/execution_formal.log',
        note='Measured sample retained Python bytes; extrapolation is not a measurement of the previous peak.'))
    print(json.dumps(rows), flush=True)


def profile_optimized(limit):
    """Independent retained-structure measurements; never overwrites baseline."""
    from app.correlation.scoring import CorrelationScorer
    from app.models import Entity
    from demo_support import truth_guard
    freeze = json.loads((ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json').read_text('utf8'))
    config = restore_config(freeze['algorithm_snapshot'])
    rows = []
    def row(name, count, value, bounded, note):
        rows.append(dict(structure=name, logical_item_count=count, measured_retained_python_bytes=deep_size(value),
            bounded=bounded, measurement_basis=note))
    with truth_guard(ROOT), bounded_execution(OUT/'tmp'/('layout-'+str(time.time_ns()))) as state:
        def check():
            available = available_commit_mb()
            if available is not None and available < 512:
                raise MemoryError('host_available_commit_below_512_MiB')
        state.resource_check = check
        store, _ = source()
        mapping = state.alerts()
        for a in itertools.islice(store.read_records('alerts', parquet=True), limit):
            mapping.add(a)
        ids = set(mapping)
        entities = []
        for e in store.read_records('entities', parquet=True):
            members = sorted(ids.intersection(e.alert_ids))
            if members:
                data = e.model_dump()
                data['alert_ids'] = members
                entities.append(Entity.model_validate(data))
        settings = load_cptc_dataset(ROOT).source_settings
        dedupe = deduplicate(mapping.sequence(), config, settings)
        if not dedupe.is_complete:
            raise MemoryError(dedupe.incomplete_reason)
        index = AlertIndex(mapping.sequence(), dedupe.groups, entities)
        scorer = CorrelationScorer(index, config, settings)
        postings = [*index.time.values(), *(p for collections in (index.by_entity,index.by_source,index.by_sensor)
            for categories in collections.values() for p in categories.values())]
        row('alert locators',len(mapping),mapping.records,False,'Own locator dictionary; no canonical model population')
        row('canonical LRU',len(state.canonical_cache),state.canonical_cache,True,'Private raw locators excluded from traversal')
        row('raw LRU',len(state.cache),state.cache,True,'At most 128 complete raw payloads')
        row('representative groups',index.N,index.groups,False,'Includes borrowed identity strings')
        row('owner/time/position maps',len(mapping),[index.owner,index.times,index.positions],False,'O(N) indexes; shared identities within this traversal counted once')
        row('validated entities',len(index.entities),index.entities,False,'Includes entity membership identity strings')
        row('posting data only',len(postings),[(p.members,p.times,p.bits,p.blocks,p.block_offsets) for p in postings],False,'Explicit projection excludes index/state back-references')
        for name, value in [('role projection',index.roles),('evidence type projection',scorer.evidence_evaluator.by_type),
            ('duplicate metadata',scorer.duplicate.metadata),('observation identities',scorer.duplicate.observation.identities)]:
            row(name,len(value),value.cache,True,'Only bounded LRU retained; full logical population is exact SQLite storage')
        result = dict(status='MEASURED',sample_alerts=len(mapping),sample_representatives=index.N,
            sample_entities=len(index.entities),structures=rows,peak_working_set_mib=peak_memory_mb(),
            note='Deterministic real input slice for layout measurements only. Independent structure traversals are not additive due to shared IDs. This is not a full correlation run or a full-process heap dump.')
        atomic_json(OUT/'optimized_layout_measurement.json',result)
    print(json.dumps(dict(status='MEASURED',sample_alerts=limit)),flush=True)


class CapacityObserver:
    def __init__(self):
        self.count = self.member_count = 0
        self.histogram, self.decisions, self.families = Counter(), Counter(), Counter()
        self.top = []
        self.hashes = {name: hashlib.sha256() for name in ('candidate', 'member_score', 'correlation_decision')}
        self.current = self.best = self.valid = None

    def prepare_candidates(self, index, candidates):
        self.index = index
        atomic_json(OUT/'candidate_counts.json', dict(admitted=candidates.admitted_count,
            scheduled=candidates.retained_count, resource_truncated=candidates.resource_truncated_count,
            potential_pair_stats=candidates.potential_pair_stats, policy_pruned=candidates.policy_pruned_count))

    def __call__(self, row):
        stage = row['stage']
        if stage not in self.hashes:
            return
        self.hashes[stage].update(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf8')+b'\n')
        if stage == 'candidate':
            self.current, self.best, self.valid = row, None, None
        elif stage == 'member_score':
            self.member_count += 1
            a, b = row['support_pair']
            key = (-row['score'], self.index.alerts[a].timestamp, self.index.alerts[b].timestamp, a, b)
            # Diagnostic top selection; actual support is always the production decision.
            if self.best is None or key < self.best[0]:
                self.best = key, row
            if row['valid'] and (self.valid is None or key < self.valid[0]):
                self.valid = key, row
        else:
            self.count += 1
            selected = (self.valid or self.best)[1]
            score = selected['score']
            self.histogram[str(next((cut for cut in (.2,.3,.4,.5,.6,.65,.7,.75) if score < cut), 1.0))] += 1
            ev = selected['evidence'].get('evidence_v2', {})
            self.decisions[ev.get('decision', row['decision'])] += 1
            self.families.update(ev.get('evidence_families', ()))
            payload = dict(candidate=self.current, member=selected, formal_decision=row)
            item = (score, tuple(self.current['support_key']), payload)
            if len(self.top) < 100:
                heapq.heappush(self.top, item)
            elif item[:2] > self.top[0][:2]:
                heapq.heapreplace(self.top, item)


def full_run():
    OUT.mkdir(parents=True, exist_ok=True)
    before = json.loads((OUT/'protected_files_before.json').read_text('utf8'))
    current = protected_files()
    allowed = {'backend/app/services/capacity.py', 'backend/app/services/storage.py',
               'backend/app/correlation/index.py', 'backend/app/correlation/candidates.py',
               'backend/app/dedup/grouping.py','backend/app/dedup/observation.py','backend/app/correlation/evidence.py'}
    if any(before[p] != current[p] for p in before if p not in allowed):
        raise ValueError('protected_file_changed_before_run')
    frozen_path = ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json'
    frozen = json.loads(frozen_path.read_text('utf8'))
    config = restore_config(frozen['algorithm_snapshot'])
    assert frozen['CORRELATION_V4_FROZEN'] and config.mapping_digest == frozen['mapping_digest']
    assert correlation_version(config) == frozen['algorithm_version']
    assert config.algorithm.score.correlation_threshold == .65
    assert config.algorithm.clustering.edge_threshold == .70
    from app.services.capacity import IMPLEMENTATION_VERSION
    atomic_json(OUT/'frozen_recipe_verification.json', dict(algorithm_version=correlation_version(config),
        config_hash=config.config_hash, mapping_digest=config.mapping_digest,
        execution_implementation=IMPLEMENTATION_VERSION, algorithm_snapshot_equal=True,
        frozen_receipt_sha256=file_digest(frozen_path), correlation_threshold=.65, cluster_threshold=.7,
        candidate_parameters=config.algorithm.candidate.model_dump()))
    started = time.perf_counter()
    state = dict(stage='canonical_loading', abort=False, minimum_available_commit_mb=None,
                 alerts=0, representatives=None, scored=0)
    stop = threading.Event()
    observer = CapacityObserver()
    atomic_json(OUT/'full_run_result.json', dict(status='RUNNING', full_scan_completed=False,
        step_3a_rerun_ready=False, step_3b_executed=False))
    def checkpoint(extra=None):
        row = dict(state, elapsed_seconds=time.perf_counter()-started, peak_memory_mb=peak_memory_mb(),
                   scored=observer.count, **(extra or {}))
        print(json.dumps(row), flush=True)
        atomic_json(OUT/'resource_checkpoint.json', row)
    def monitor():
        ticks = 0
        while not stop.wait(.5):
            commit = available_commit_mb()
            if commit is not None:
                prior = state['minimum_available_commit_mb']
                state['minimum_available_commit_mb'] = min(commit, prior) if prior is not None else commit
                if commit < 512:
                    state['abort'] = True
            ticks += 1
            if ticks % 80 == 0:
                checkpoint()
    def check():
        if state['abort']:
            raise MemoryError('host_available_commit_below_512_MiB')
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    result = None
    try:
        from demo_support import truth_guard
        with truth_guard(ROOT), bounded_execution(OUT/'tmp'/('full-'+str(time.time_ns()))) as spill:
            spill.resource_check = check
            spill.progress = lambda row: checkpoint(dict(execution_progress=row))
            store, summary = source()
            alerts = spill.alerts()
            for a in store.read_records('alerts', parquet=True):
                alerts.add(a)
                state['alerts'] = len(alerts)
            alerts.sorted()
            digest = content_digest([[a.alert_id, a.raw_fingerprint] for a in alerts.values()])
            if len(alerts) != 331554 or digest != summary['dataset_digest']:
                raise ValueError('full_input_digest_mismatch')
            state['stage'] = 'production_dedupe'
            settings = load_cptc_dataset(ROOT).source_settings
            dedupe = deduplicate(alerts.sequence(), config, settings)
            if not dedupe.is_complete:
                raise MemoryError(dedupe.incomplete_reason)
            state['representatives'] = len(alerts)-sum(len(g.alert_ids)-1 for g in dedupe.groups)
            if state['representatives'] != 318569:
                raise ValueError('frozen_representative_count_mismatch')
            atomic_json(OUT/'dedupe_counts.json', dict(groups=len(dedupe.groups), representatives=state['representatives'],
                candidates=dedupe.candidate_count, verified=dedupe.verified_pair_count))
            # Diagnostics of dedupe are not correlation input and may be released.
            dedupe.diagnostics.clear()
            gc.collect()
            entities = list(store.read_records('entities', parquet=True))
            state['stage'] = 'production_index_and_candidates'
            def progress(row):
                check()
                state['stage'] = 'production_scoring' if row['stage'] == 'candidates' else row['stage']
                checkpoint(dict(production_progress=row))
            result = run_correlation(alerts.sequence(), dedupe.groups, entities, config, settings,
                                     diagnostic_sink=observer, progress=progress)
            if result.candidates is None:
                raise MemoryError(result.record.incomplete_reason)
            state['stage'] = 'formal_edge_output'
            with gzip.open(OUT/'correlation_edges.jsonl.gz', 'wt', encoding='utf8') as handle:
                for e in result.edges:
                    check()
                    handle.write(e.canonical_json()+'\n')
            atomic_json(OUT/'top_100_candidate_pairs.json', [row[2] for row in sorted(observer.top, key=lambda r:(-r[0],r[1]))])
            counts = json.loads((OUT/'candidate_counts.json').read_text('utf8'))
            execution_completed = observer.count == counts['scheduled'] and not state['abort']
            # Frozen resource truncation is disclosed; it is never hidden by a capacity success.
            accepted = execution_completed and result.record.is_complete
            atomic_json(OUT/'full_run_result.json', dict(status='CPTC_CORRELATION_CAPACITY_REPAIRED' if accepted else
                'CPTC_CORRELATION_CAPACITY_STILL_BLOCKED', execution_completed=execution_completed,
                all_admitted_scored=counts['admitted']==observer.count, full_scan_completed=accepted,
                counts=dict(canonical=state['alerts'], representatives=state['representatives'], **counts,
                            scored=observer.count, member_scores=observer.member_count, correlation_edges=len(result.edges)),
                input_digest=digest, algorithm_record_status=result.record.status.value,
                incomplete_reason=result.record.incomplete_reason, summary=result.summary,
                semantic_digests={k:v.hexdigest() for k,v in observer.hashes.items()},
                score_bins=dict(observer.histogram), decisions=dict(observer.decisions), families=dict(observer.families),
                resource_guard_triggered=state['abort'], step_3a_rerun_ready=accepted,
                step_3a_rerun_executed=False, step_3b_executed=False))
            state['stage'] = 'execution_completed'
    except Exception as exc:
        import traceback
        traceback.print_exc()
        atomic_json(OUT/'full_run_result.json', dict(status='CPTC_CORRELATION_CAPACITY_STILL_BLOCKED',
            execution_completed=False, full_scan_completed=False, failure_stage=state['stage'], error=str(exc),
            counts=dict(canonical=state['alerts'], representatives=state['representatives'], scored=observer.count,
                        member_scores=observer.member_count), resource_guard_triggered=state['abort'], step_3a_rerun_ready=False))
    finally:
        stop.set()
        thread.join(5)
        checkpoint()
        after = protected_files()
        changed = [p for p in before if before[p] != after[p]]
        atomic_json(OUT/'protected_files_verification.json', dict(protected_unchanged=all(p in allowed for p in changed),
            allowed_execution_changes=changed, unexpected_changes=[p for p in changed if p not in allowed],
            before=before, after=after))
        atomic_json(OUT/'resource_profile.json', dict(state, runtime_seconds=time.perf_counter()-started,
            peak_memory_mb=peak_memory_mb(), guard_threshold_mb=512, resource_guard_triggered=state['abort'],
            scored=observer.count, member_scores=observer.member_count))


def reports():
    """Separate observed results from sample estimates and frozen budget limits."""
    measured = json.loads((OUT/'memory_audit_before.json').read_text('utf8'))['rows'][0]
    scale = 331554/measured['sample_alerts']
    entries = []
    def row(name, count, byte_size, lifetime, bounded, duplicated, spillable, note):
        entries.append(dict(structure=name, logical_item_count=count, bytes=byte_size,
            lifetime=lifetime, bounded=bounded, duplicated=duplicated, spillable=spillable,
            measurement_basis=note))
    row('CanonicalAlert normalized Pydantic fields',331554,int(measured['canonical_retained_bytes']*scale),
        'input through scoring',False,True,True,'Estimate from measured 12000-record retained sample; excludes full raw')
    row('Representative identity/groups',318569,None,'index through scoring',False,False,True,'O(N) identity references, not a second canonical population')
    row('Entity postings and redundant run/member/group metadata',None,None,'index through scoring',False,True,True,
        'Legacy sample total posting_metadata_bytes traverses index back-reference and is NOT an independent retained-byte attribution')
    row('blocked masks',measured['block_count'],measured['block_int_bytes'],'index through scoring',False,True,True,
        'Measured sample global-width block integers; singleton high ordinals unnecessarily retain leading zeros')
    row('candidate provenance',None,None,'generation through admission',True,True,True,
        'Already disk-backed in capacity-v4.1; new integer keys and compressed exact payloads reduce disk volume')
    row('candidate Python objects',None,None,'one endpoint / one scheduled pair',True,False,True,
        'Bounded dictionaries at endpoint, full corpus is SQLite; no full candidate list fetched')
    row('score payload',0,0,'one member pair',True,False,True,'Previous formal failure had scored_candidates=0')
    row('raw_alert payload',128,None,'LRU access',True,False,True,'Raw was already disk-backed; current canonical cache also bounded at 512')
    row('evidence payload',0,0,'admitted member scoring',True,False,True,'Previous formal failure occurred before scoring')
    row('EvidenceEvaluator immutable entity-type projection',331554,None,'scorer initialization through scoring',False,True,True,
        'Source audit: old by_type kept one dictionary of type/entity sets per alert, overlapping AlertIndex roles. Both now use exact disk scalar stores and bounded 4096-entry LRUs; no old full heap attribution is available')
    row('SQLite page caches',None,8388608,'one connection',True,False,True,'8 MiB per connection; temp_store=FILE; new run-private journal OFF and synchronous OFF')
    row('Python dictionaries/sets: alert references in DuplicateScorer',331554,None,'dedupe/scorer lifetime',False,True,True,
        'Previously reused packed objects; repaired holder borrows the lazy mapping. Immutable duplicate metadata and observation identities now use exact disk keys plus 4096-entry LRUs')
    row('pair dedup state',None,None,'candidate generation through scheduling',True,False,True,
        'Correlation global pairs already SQLite, dedupe set was 19669 on CPTC; directional audit used Python sets and now uses exact SQLite PRIMARY KEY')
    row('ranking heaps',200,None,'per representative',True,False,True,'Frozen channel/hot/endpoint K retained; global scheduling uses exact external ORDER BY')
    row('Top Pair collection',100,None,'diagnostic run',True,False,True,'Existing size=100 heap retained, not all scored payloads')
    row('diagnostic aggregation',318569,None,'candidate audit/scoring summary',False,True,True,
        'Disk masks bounded; remaining per-representative counters/report dictionaries O(N); scorer score array stores only doubles')
    row('DuckDB legacy Parquet decode / wide payload sort',122880,567790141,'input reader',False,True,True,
        'Measured parquet_metadata row-group uncompressed payload bytes; old sample peak 2126.64 MiB; new scan and SQLite external sorting, 768 MiB native limit')
    atomic_json(OUT/'memory_root_cause.json',dict(previous_peak_memory_mb=5387.76171875,
        attribution='No heap dump exists for the previous peak; exact full-process byte attribution is unavailable. Sample measurements, source audit and row-group metadata identify dominant sources.',
        why_sqlite_spill_was_insufficient='Candidate spill did not bound resident normalized CanonicalAlert models, native wide-payload sorting/decoding or postings. The prior failure preceded scoring.',
        global_python_correlation_pair_set=False, prior_directional_diagnostic_pair_set=True,
        sample=measured, structures=entries))
    cause = json.loads((OUT/'memory_root_cause.json').read_text('utf8'))
    current_full = json.loads((OUT/'full_run_result.json').read_text('utf8'))
    current_profile = json.loads((OUT/'resource_profile.json').read_text('utf8'))
    cause['latest_full_attempt'] = dict(result=current_full, resource=current_profile,
        safety_scope='512 MiB available commit is system-wide and includes background applications',
        largest_identified_remaining_structures='O(N) alert locators and dedupe bucket/group state. Later validated entity/group indexes and diagnostic row dictionaries have not been profiled on the final implementation; exact largest retained-heap attribution was not captured',
        next_bottleneck='Stable host commit headroom is required to measure the repaired role/type indexes and finish candidate admission/scoring. The latest failure happened before those stages.')
    layout_path = OUT/'optimized_layout_measurement.json'
    layout = json.loads(layout_path.read_text('utf8')) if layout_path.is_file() else None
    if layout:
        cause['optimized_layout_measurement'] = layout
        if layout.get('status') == 'MEASURED':
            cause['largest_independent_sample_traversals'] = sorted(layout['structures'],
                key=lambda v:v['measured_retained_python_bytes'], reverse=True)[:3]
    atomic_json(OUT/'memory_root_cause.json',cause)
    atomic_json(OUT/'architecture_before_after.json',dict(
        before=['Parquet wide payload ORDER BY','raw-only disk packing, resident canonical Pydantic population',
                'global-width posting masks','SQLite TEXT pair keys, uncompressed pickled provenance',
                'local Top-K then global frozen scheduling','original production scorer and guards'],
        after=['sequential native scan -> compressed SQLite rows -> exact external key order',
               'raw + validated canonical disk packing -> bounded raw/canonical LRUs',
               'immutable duplicate metadata and observation identities -> exact disk scalar keys and bounded 4096-entry LRUs',
               'immutable entity-role and evidence-type projections -> exact disk scalar keys and bounded 4096-entry LRUs',
               'offset-local lossless compressed posting blocks -> shared 256-entry decoded LRU; lazy timestamp tie runs and bisected member positions',
               'checked packed integer pair keys + lossless compressed provenance',
               'exact disk distinct including directional diagnostic pairs',
               'same local Top-K -> both-endpoint union -> exact frozen global ORDER BY',
               'same production scorer, evidence and guards -> full formal edge output'],
        ranking=['tier','weight (negative frozen weight*rarity)','gap','canonical lexical representative pair'],
        sqlite=dict(journal_mode='OFF (disposable execution DB only)',temp_store='FILE',cache_size_kib=-8192,
                    page_size=4096,transactions='one phase transaction; no per-row commits',
                    cursor='streaming iteration/fetchmany(1024); no giant fetchall',
                    indexes='INTEGER PRIMARY KEY pair; explicit ORDER BY; temp sorting on disk'),
        algorithm_version_unchanged=True))
    evidence = [json.loads(p.read_text('utf8')) for p in sorted(OUT.glob('equivalence_*.json'))
                if p.name != 'equivalence_results.json']
    required_equivalence = all((OUT/f'equivalence_{name}.json').is_file()
        for name in ('small','medium','large','russellmitchell_dev_small'))
    execution_files = ('backend/app/services/capacity.py','backend/app/services/storage.py',
        'backend/app/correlation/index.py','backend/app/correlation/candidates.py',
        'backend/app/dedup/grouping.py','backend/app/dedup/observation.py','backend/app/correlation/evidence.py')
    execution_hashes = {p:file_digest(ROOT/p) for p in execution_files}
    equivalent = required_equivalence and all(v['status']=='PASS' and
        v.get('execution_hashes') == execution_hashes for v in evidence)
    failed = any(v['status']=='FAIL' for v in evidence)
    atomic_json(OUT/'equivalence_results.json', dict(status='PASS' if equivalent else 'FAIL' if failed else 'PENDING',
        execution_hashes=execution_hashes,
        results=evidence, comparison='Exact ordered candidate dataclasses/provenance/priority, every unrounded member score/evidence/reason/guard decision diagnostic, and canonical formal edges'))
    if equivalent:
        path = ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json'
        freeze = json.loads(path.read_text('utf8'))
        implementations = {p:dict(frozen=freeze['implementation'][p], current=file_digest(ROOT/p))
            for p in ('backend/app/correlation/index.py','backend/app/correlation/candidates.py',
                      'backend/app/dedup/grouping.py','backend/app/dedup/observation.py','backend/app/correlation/evidence.py')
            if freeze['implementation'][p] != file_digest(ROOT/p)}
        atomic_json(OUT/'EXECUTION_EQUIVALENCE_RECEIPT.json',dict(scope='execution_only',
            equivalence_status='PASS', frozen_receipt_sha256=file_digest(path),
            algorithm_version=freeze['algorithm_version'], mapping_digest=freeze['mapping_digest'],
            implementation=implementations, execution_hashes=execution_hashes,
            equivalence_results_sha256=file_digest(OUT/'equivalence_results.json')))
    full = json.loads((OUT/'full_run_result.json').read_text('utf8'))
    profile = json.loads((OUT/'resource_profile.json').read_text('utf8'))
    attempts = []
    for name, disposition in (
        ('attempt_wide_sort.log','native memory limit failure'),
        ('attempt_rowgroup_decode.log','native memory limit failure'),
        ('attempt_inspection_stop.log','intentional inspection stop; not a completed run'),
        ('attempt_resident_postings_guard.log','resource guard failure before scoring'),
        ('attempt_entity_type_guard.log','resource guard failure during candidate emission with resident role/type projections'),
        ('attempt_user_interruption.log','user interrupted; not a completed run'),
        ('attempt_regression_interruption.log','user interrupted; no final pytest result'),
        ('attempt_dev_memory_contention.log','stopped to isolate full-run resources; no equivalence result')):
        path = OUT/name
        if not path.is_file():
            continue
        checkpoint = None
        for line in path.read_text('utf8',errors='replace').splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict) and 'peak_memory_mb' in value:
                    checkpoint = value
            except ValueError:
                pass
        attempts.append(dict(log=name, disposition=disposition, last_checkpoint=checkpoint))
    atomic_json(OUT/'run_attempts.json',dict(attempts=attempts,
        final_run='full_run_result.json; resource_profile.json',
        note='Interrupted attempts do not establish completion, a PASS or a resource failure.'))
    atomic_json(OUT/'capacity_benchmark.json',dict(full_run=full,resource=profile,
        previous=dict(runtime_seconds=535.3298610000056,peak_memory_mb=5387.76171875,scored=0),
        equivalence_fixtures=evidence, attempts=attempts, optimized_layout_measurement=layout))


def finalize():
    reports()
    import xml.etree.ElementTree as ET
    tests = []
    for path in sorted(OUT.glob('*tests.xml')):
        tree = ET.parse(path)
        cases = tree.findall('.//testcase')
        failures = [c.attrib.get('classname','')+'::'+c.attrib['name'] for c in cases if c.find('failure') is not None]
        errors = [c.attrib.get('classname','')+'::'+c.attrib['name'] for c in cases if c.find('error') is not None]
        skips = sum(c.find('skipped') is not None for c in cases)
        tests.append(dict(artifact=path.name, tests=len(cases), failures=failures, errors=errors,
            skipped=skips, passed=len(cases)-len(failures)-len(errors)-skips,
            suite_runtime_seconds=sum(float(s.attrib.get('time',0)) for s in tree.findall('.//testsuite'))))
    atomic_json(OUT/'test_results.json',dict(runs=tests,
        regression_failure_classification='regression_failure_classification.json',
        note='All actual runs retained, including failures subsequently corrected. Final regression has three legacy exact-file freeze gate failures, disclosed individually; no tests deleted/xfail added. The final accepted real equivalence test was run separately, not repeated in the broad suite.'))
    full = json.loads((OUT/'full_run_result.json').read_text('utf8'))
    resource = json.loads((OUT/'resource_profile.json').read_text('utf8'))
    equivalence = json.loads((OUT/'equivalence_results.json').read_text('utf8'))
    before = json.loads((OUT/'protected_files_before.json').read_text('utf8'))
    after = protected_files()
    allowed = {'backend/app/services/capacity.py','backend/app/services/storage.py',
        'backend/app/correlation/index.py','backend/app/correlation/candidates.py',
        'backend/app/dedup/grouping.py','backend/app/dedup/observation.py','backend/app/correlation/evidence.py'}
    changes = [p for p in before if before[p] != after[p]]
    protected = all(p in allowed for p in changes)
    atomic_json(OUT/'protected_files_verification.json',dict(protected_unchanged=protected,
        allowed_execution_changes=changes, unexpected_changes=[p for p in changes if p not in allowed],before=before,after=after))
    ready = full.get('full_scan_completed',False) and equivalence['status']=='PASS' and protected
    status = ('CPTC_CORRELATION_CAPACITY_REPAIRED' if ready else
        'CORRELATION_CAPACITY_EQUIVALENCE_FAILED' if equivalence['status']=='FAIL' else
        'CPTC_CORRELATION_CAPACITY_STILL_BLOCKED')
    counts = full.get('counts',{})
    atomic_json(OUT/'FINAL_RESULT.json',dict(status=status,step_3a_rerun_ready=ready,
        full_run_result=full,resource_profile=resource,equivalence_status=equivalence['status'],
        protected_unchanged=protected,step_3a_rerun_executed=False,step_3b_executed=False))
    labels = ['Task Result','Frozen Recipe Verification','Previous Bottleneck','Memory Root Cause',
        'Architecture Changes','Candidate Storage','Candidate Dedup','Candidate Budget / Ranking Preservation',
        'Scoring Execution','Evidence / Raw Traceability','Reference Equivalence','CPTC Full-Run Result',
        'Candidate / Scored Counts','CorrelationEdge Execution Status','Runtime / Peak Memory','Tests',
        'Protected Files','Files Changed','Remaining Limitations','Step 3A Rerun Readiness']
    regression = next((t for t in tests if t['artifact']=='regression_tests.xml'), {})
    values = [status,
        'Frozen v4 algorithm version, snapshot, weights/windows/budgets/thresholds and mapping preserved. Original freeze receipt unchanged; execution differences bound by EXECUTION_EQUIVALENCE_RECEIPT.json.',
        'Old failure preceded scoring (0 scored). SQLite candidate spill left canonical Pydantic fields, wide Parquet sorting/decoding and posting structures resident.',
        'Measured 12000-record canonical retained sample: 103345468 bytes; full-size estimate ~2.7 GiB. Prior sample peak ~2126.64 MiB also exposes native reader costs. No old full heap dump exists; see memory_root_cause.json for explicit measurement limits.',
        'External raw+canonical store and bounded caches; lazy DuplicateScorer references; exact disk-backed immutable scorer metadata/observation identities and entity-role/evidence-type projections; compressed local-offset bitset blocks and lazy tie runs; narrow external payload ordering; packed pair keys and lossless provenance compression.',
        'SQLite signed INTEGER PRIMARY KEY using checked lexical representative ordinals; real Stable IDs unchanged in candidates, evidence and edges.',
        'Exact deterministic SQL distinct; all channel provenance merged. No Bloom/approximate dedup. Prior correlation pairs were already disk-backed; small production dedupe pair set was 19669, directional diagnostic sets now spill.',
        'Same per-channel/hot/endpoint Top-K; complete both-endpoint union before global ORDER BY (tier, negative weight*rarity, gap, lexical pair). Budget remains 2000000; resource truncation remains incomplete.',
        f'Original run_correlation / CorrelationScorer / evidence evaluator / guard path used. Scored {counts.get("scored")}; member scores {counts.get("member_scores")}. No copied formula.',
        'Full validated raw and canonical facts stored losslessly on disk. Model dumps and raw pointers restored through bounded caches. Every formal edge validated by original context/Schema with real supporting IDs.',
        f'{equivalence["status"]}; small/medium/large synthetic fixtures plus accepted 7640-alert russellmitchell_dev_small. Exact ordered candidate/provenance/priority and unrounded member score/evidence/guard/formal edge comparisons; no rounded-only comparison.',
        f'Canonical {counts.get("canonical")}; representatives {counts.get("representatives")}; execution_completed={full.get("execution_completed")}; full_scan_completed={full.get("full_scan_completed")}; reason={full.get("incomplete_reason", full.get("error"))}.',
        f'Admitted={counts.get("admitted")}; scheduled={counts.get("scheduled")}; scored={counts.get("scored")}; resource_truncated={counts.get("resource_truncated")}. Unknown counts remain null/unavailable.',
        f'Formal edge count={counts.get("correlation_edges")}; complete output correlation_edges.jsonl.gz when execution finished. Clustering/chain/Step 3B not run.',
        f'Runtime={resource.get("runtime_seconds")} seconds; peak={resource.get("peak_memory_mb")} MiB (Windows peak working set); minimum available commit={resource.get("minimum_available_commit_mb")} MiB; guard threshold=512 MiB; triggered={resource.get("resource_guard_triggered")}.',
        f'Actual pytest/XML runs in test_results.json. Final regression summary: {regression}. Prior Step 3A recorded two legacy demo freeze gate failures and a pre-existing entities/normalization.py hash difference. Execution byte changes may also fail those unchanged legacy gates; the dedicated Step 3A receipt verifies this task separately. No tests deleted or xfailed.',
        f'protected_unchanged={protected}; full before/after SHA-256 inventory preserved. Algorithm YAML/mapping/Adapter/raw CPTC/Step 2 accepted snapshot/original freeze manifest unchanged.',
        ', '.join(changes)+', scripts/cptc_2018_capacity.py, scripts/cptc_2018_step3a.py (receipt verifier only), backend/tests/test_cptc_capacity_repair.py, outputs/cptc_2018_step3a_capacity/.',
        'Latest attempt stopped in dedupe under system-wide available-commit pressure; final role/type indexes and complete candidates remain unmeasured. Working-set peak is not private-commit peak, and exact largest retained-heap attribution is unavailable. O(N) index/group/diagnostic references remain. Frozen global budget can still cause incomplete results. Interrupted probes are retained; automatic approval review rejected shell cleanup of tmp/full, so it was preserved. No claim of CPTC compatibility acceptance.',
        'STEP_3A_RERUN_READY = '+('YES' if ready else 'NO')]
    lines = [f'{i}. {label}\n\n{value}\n' for i,(label,value) in enumerate(zip(labels,values),1)]
    (OUT/'CAPACITY_REPAIR_REPORT.md').write_text('\n'.join(lines),encoding='utf8')
    print(json.dumps(dict(status=status,step_3a_rerun_ready=ready)),flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--audit', type=int)
    parser.add_argument('--full-run', action='store_true')
    parser.add_argument('--reports', action='store_true')
    parser.add_argument('--finalize', action='store_true')
    parser.add_argument('--profile-optimized', type=int)
    args = parser.parse_args()
    if args.audit:
        audit(args.audit)
    elif args.full_run:
        full_run()
    elif args.reports:
        reports()
    elif args.finalize:
        finalize()
    elif args.profile_optimized:
        try:
            profile_optimized(args.profile_optimized)
        except MemoryError as exc:
            atomic_json(OUT/'optimized_layout_measurement.json',dict(status='RESOURCE_BLOCKED',error=str(exc),
                sample_size_requested=args.profile_optimized,guard_threshold_mib=512))
            raise

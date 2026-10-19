"""Execution equivalence against the captured, unmodified v4 reference path."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest

from app.correlation import edges
from app.correlation.index import TemporalPosting
from app.services.capacity import bounded_execution, DiskPairObjects, schedule_pairs
from app.services.storage import SnapshotStore, restore_config
from test_correlation_score import alert, inputs, group, parent_child

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'outputs/cptc_2018_step3a_capacity'


@contextmanager
def reference(monkeypatch):
    modules = []
    with monkeypatch.context() as patch:
        for name in ('index', 'candidates'):
            path = OUT/'reference/backend/app/correlation'/f'{name}.py'
            if not path.exists():
                pytest.fail('Captured pre-repair v4 reference is required')
            before = json.loads((OUT/'protected_files_before.json').read_text('utf8'))
            assert hashlib.sha256(path.read_bytes()).hexdigest() == before[f'backend/app/correlation/{name}.py']
            spec = importlib.util.spec_from_file_location('capacity_reference_'+name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            modules.append(spec.name)
            patch.setattr(edges, 'AlertIndex' if name == 'index' else 'generate_candidates',
                          module.AlertIndex if name == 'index' else module.generate_candidates)
        from app.correlation import scoring
        path = OUT/'reference/backend/app/dedup_grouping.py'
        spec = importlib.util.spec_from_file_location('app.dedup.capacity_reference_grouping', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules.append(spec.name)
        before = json.loads((OUT/'protected_files_before.json').read_text('utf8'))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before['backend/app/dedup/grouping.py']
        patch.setattr(scoring, 'DuplicateScorer', module.DuplicateScorer)
        yield
    for name in modules:
        sys.modules.pop(name, None)


def recipe():
    freeze = json.loads((ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json').read_text('utf8'))
    return restore_config(freeze['algorithm_snapshot'])


def semantic_digest():
    hashes = {s: hashlib.sha256() for s in ('candidate', 'member_score', 'correlation_decision')}
    counts = dict.fromkeys(hashes, 0)
    def sink(row):
        if row['stage'] in hashes:
            name = row['stage']
            hashes[name].update(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf8')+b'\n')
            counts[name] += 1
    return sink, hashes, counts


EXECUTION_FILES = ('backend/app/services/capacity.py', 'backend/app/services/storage.py',
    'backend/app/correlation/index.py', 'backend/app/correlation/candidates.py',
    'backend/app/dedup/grouping.py', 'backend/app/dedup/observation.py', 'backend/app/correlation/evidence.py')


def execution_hashes():
    return {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in EXECUTION_FILES}


def compare(aa, groups, entities, settings, config, tmp_path, monkeypatch, label):
    # A stale PASS must never attest to a later execution implementation.
    path = OUT/f'equivalence_{label}.json'
    before = execution_hashes()
    path.write_text(json.dumps(dict(status='PENDING', execution_hashes=before)), encoding='utf8')
    try:
        _compare(aa, groups, entities, settings, config, tmp_path, monkeypatch, label)
        assert execution_hashes() == before
        evidence = json.loads(path.read_text('utf8'))
        evidence.update(execution_hashes=before, config_hash=config.config_hash,
                        mapping_digest=config.mapping_digest)
        path.write_text(json.dumps(evidence, indent=2), encoding='utf8')
    except BaseException as exc:
        path.write_text(json.dumps(dict(status='FAIL' if isinstance(exc, AssertionError) else 'ERROR',
            error=type(exc).__name__+': '+str(exc), execution_hashes=before)), encoding='utf8')
        raise


def _compare(aa, groups, entities, settings, config, tmp_path, monkeypatch, label):
    sink_a, digest_a, counts_a = semantic_digest()
    with reference(monkeypatch):
        expected = edges.run_correlation(aa, groups, entities, config, settings, diagnostic_sink=sink_a)
    sink_b, digest_b, counts_b = semantic_digest()
    with bounded_execution(tmp_path/'spill') as state:
        mapping = state.alerts()
        for a in reversed(aa):
            mapping.add(a)
        actual = edges.run_correlation(mapping.sequence(), groups, entities, config, settings, diagnostic_sink=sink_b)
        assert len(actual.candidates.pairs) == len(expected.candidates.pairs)
        for actual_pair, expected_pair in zip(actual.candidates.pairs, expected.candidates.pairs, strict=True):
            assert asdict(actual_pair) == asdict(expected_pair)
        assert list(actual.candidates.diagnostics) == expected.candidates.diagnostics
        assert actual.candidates.admitted_degrees == expected.candidates.admitted_degrees
        assert actual.candidates.potential_pair_stats == expected.candidates.potential_pair_stats
        assert actual.candidates.candidate_admission_stats == expected.candidates.candidate_admission_stats
        assert counts_a == counts_b
        hashes = {k:v.hexdigest() for k,v in digest_a.items()}
        assert hashes == {k:v.hexdigest() for k,v in digest_b.items()}
        assert [e.canonical_json() for e in actual.edges] == [e.canonical_json() for e in expected.edges]
        assert actual.record.status == expected.record.status
        assert len(state.canonical_cache) <= 512 and len(state.cache) <= 128
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/f'equivalence_{label}.json').write_text(json.dumps(dict(status='PASS', alerts=len(aa),
        representatives=expected.summary['representative_alert_count'], candidates=counts_a['candidate'],
        member_scores=counts_a['member_score'], formal_edges=len(expected.edges),
        candidate_order_and_provenance=True, unrounded_member_score_and_evidence=True,
        guard_and_formal_decision=True, semantic_digests=hashes), indent=2), encoding='utf8')


@pytest.mark.parametrize('size,label', [(24,'small'), (96,'medium'), (320,'large')])
def test_capacity_tiers_exact_reference_semantics(size, label, tmp_path, monkeypatch):
    # Synthetic, deterministic ties, hotspots, member groups, relations,
    # semantic fallback, rare resource and boundary-window categories.
    aa = parent_child()
    aa += [alert('capacity-'+str(i), (i//3)*17, host='h'+str(i%9), account='u'+str(i%7),
                 file='/tmp/resource-'+str(i%11), category='web_attack' if i%4 == 0 else 'unknown',
                 rule_id='r'+str(i%5)) for i in range(size-8)]
    aa += [alert('semantic-'+str(i), 600+i, rule_id='s', signature='s') for i in range(6)]
    groups = [group(aa[2:5]), group(aa[11:14])]
    index, settings = inputs(aa, groups=groups)
    compare(list(index.alerts.values()), groups, list(index.entities.values()), settings, recipe(),
            tmp_path, monkeypatch, label)


def test_resource_budget_tie_break_and_dropped_provenance(tmp_path, monkeypatch):
    # Test-only small resource budget; production frozen config is untouched.
    config = recipe().snapshot
    config['candidate']['max_candidate_pairs'] = 7
    config = restore_config(config)
    aa = [alert('budget-'+str(i), i//3, host='h', account='u', session='s', rule_id='r') for i in range(48)]
    idx, settings = inputs(aa)
    compare(list(idx.alerts.values()), [], list(idx.entities.values()), settings, config,
            tmp_path, monkeypatch, 'budget_ties')


def test_fact_metadata_eviction_recomputes_exact_scores(tmp_path, monkeypatch):
    from app.services.capacity import DiskScalarObjects
    constructor = DiskScalarObjects.__init__
    monkeypatch.setattr(DiskScalarObjects, '__init__', lambda self,db,name,limit=4096:
                        constructor(self,db,name,limit=4))
    aa = parent_child()+[alert('eviction-'+str(i), i*5, host='h'+str(i%4),account='u') for i in range(40)]
    idx, settings = inputs(aa)
    compare(list(idx.alerts.values()), [], list(idx.entities.values()), settings, recipe(),
            tmp_path, monkeypatch, 'metadata_eviction')


def test_sparse_high_ordinal_masks_have_local_width(tmp_path):
    index = SimpleNamespace(times={'a':0,'b':1}, positions={'a':1000000,'b':1000001},
                            owner={'a':'a','b':'b'},groups={'a':('a',),'b':('b',)})
    with bounded_execution(tmp_path/'spill'):
        posting = TemporalPosting(['a','b'], index)
        assert posting.block_mask(0) == 3
        assert posting.block_offsets == [1000000]
        assert posting.mask(0,1) == (3 << 1000000)
        assert posting.mask(0,1,excluded={'a'}) == 1 << 1000001


def test_integer_pair_dedup_and_sql_ranking(tmp_path):
    reps = tuple('id-'+str(i) for i in range(8))
    idx = SimpleNamespace(N=8, positions={r:i for i,r in enumerate(reps)}, representatives=reps)
    with bounded_execution(tmp_path/'spill') as state:
        pairs = DiskPairObjects(state.database(), 'pairs', idx)
        payload = ((2,-.1,4.,(reps[1],reps[7])), ['provenance-a', 'provenance-b'])
        pairs[(reps[1],reps[7])] = payload
        pairs[(reps[1],reps[7])] = payload
        pairs[(reps[0],reps[6])] = ((2,-.1,4.,(reps[0],reps[6])), ['provenance-c'])
        assert len(pairs) == 2
        assert pairs[(reps[1],reps[7])] == payload
        selected = list(schedule_pairs(pairs.db, pairs, 1))
        assert selected[0][0] == (reps[0],reps[6])


def test_bounded_reader_sorts_wide_rows_without_materializing_all(tmp_path):
    records = [alert('record-'+str(i), host='h') for i in range(200)]
    store = SnapshotStore(tmp_path, 'ana_'+'2'*64)
    store.write_records('alerts', reversed(records))
    expected = list(store.read_records('alerts', parquet=True))
    with bounded_execution(tmp_path/'spill'):
        actual = list(store.read_records('alerts', parquet=True))
    assert [a.canonical_json() for a in actual] == [a.canonical_json() for a in expected]


def test_execution_receipt_cannot_authorize_scoring_change(monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import cptc_2018_step3a as diagnostic
    original = diagnostic.file_digest
    monkeypatch.setattr(diagnostic, 'file_digest', lambda path: '0'*64
        if path == ROOT/'backend/app/correlation/scoring.py' else original(path))
    with pytest.raises(ValueError, match='frozen_correlation_implementation_changed'):
        diagnostic.load_frozen_config()


def test_execution_receipt_is_bound_to_exact_equivalence_artifact(monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import cptc_2018_step3a as diagnostic
    original = diagnostic.file_digest
    monkeypatch.setattr(diagnostic, 'file_digest', lambda path: '0'*64
        if path == OUT/'equivalence_results.json' else original(path))
    with pytest.raises(ValueError, match='frozen_correlation_implementation_changed'):
        diagnostic.load_frozen_config()


def test_canonical_disk_cache_eviction_preserves_all_facts(tmp_path):
    with bounded_execution(tmp_path/'spill') as state:
        mapping = state.alerts()
        originals = [alert(str(i), host='h', account='u') for i in range(600)]
        for a in originals:
            mapping.add(a)
        assert all(isinstance(locator, tuple) for locator in mapping.records.values())
        for a in originals:
            assert mapping[a.alert_id].model_dump() == a.model_dump()
        assert state.canonical_cache.evictions > 0
        assert mapping[originals[0].alert_id].canonical_json() == originals[0].canonical_json()


def test_duplicate_scorer_keeps_lazy_mapping_and_bounded_sequence(tmp_path):
    from app.dedup.grouping import DuplicateScorer, deduplicate
    from app.config import load_config
    aa = [alert(str(i), host='h') for i in range(600)]
    idx, settings = inputs(aa)
    config = recipe()
    expected = deduplicate(list(idx.alerts.values()), config, settings)
    with bounded_execution(tmp_path/'spill') as state:
        mapping = state.alerts()
        for a in idx.alerts.values():
            mapping.add(a)
        seq = mapping.sequence()
        assert seq[0].alert_id == tuple(mapping)[0]
        assert len(state.canonical_cache) == 1
        scorer = DuplicateScorer(seq, config, settings)
        assert scorer.alerts is mapping
        from_view = DuplicateScorer(mapping.values(), config, settings)
        assert from_view.alerts is mapping
        actual = deduplicate(seq, config, settings)
        assert actual.groups == expected.groups
        assert actual.diagnostics == expected.diagnostics
        assert actual.candidate_count == expected.candidate_count


def test_accepted_russellmitchell_dev_small_reference(tmp_path, monkeypatch):
    from app.adapters.base import AdapterSettings
    path = ROOT/'outputs/correlation_v4_small/dev_v4'
    identity = 'ana_e2e8bea1a8716f1fefdfe841098a6439dc984478f8431ce83edb2e2140b26508'
    store = SnapshotStore(path, identity)
    record, _, manifest = store.read_metadata()
    assert record.is_complete and record.metrics.alert_count == 7640
    settings = {key: AdapterSettings(**value) for key,value in record.config_snapshot['sources'].items()}
    config = restore_config(record.config_snapshot['algorithm'])
    assert config.snapshot == recipe().snapshot
    compare(list(store.read_records('alerts', parquet=True)), list(store.read_records('dedupe_groups', parquet=True)),
            list(store.read_records('entities', parquet=True)), settings, config, tmp_path, monkeypatch,
            'russellmitchell_dev_small')

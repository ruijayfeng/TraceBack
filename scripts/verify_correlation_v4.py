"""Development replay and exact observation; only russellmitchell/fox, no GT."""
import argparse
from array import array
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'scripts'))
from app.services import bounded_diagnostics as diagnostics
from app.services.analysis import AnalysisService
from app.services.datasets import load_dataset
from app.services.storage import SnapshotStore, atomic_json
from app.correlation.edges import correlation_version
from demo_support import truth_guard


def quantiles(values):
    values = sorted(values)
    result = {}
    for name, q in [('P50', .5), ('P75', .75), ('P90', .9), ('P95', .95), ('P99', .99), ('MAX', 1.)]:
        if not values:
            result[name] = None
        else:
            p = (len(values)-1)*q
            lo = int(p)
            result[name] = values[lo]+(values[min(lo+1, len(values)-1)]-values[lo])*(p-lo)
    return result


class DevelopmentObserver(diagnostics.BoundedDiagnostics):
    """Read-only observer of the existing full-member selection, no decisions."""
    def __init__(self, *args):
        super().__init__(*args)
        self.scores = {k: array('d') for k in ('all', 'accepted', 'rejected')}
        self.composition = {k: Counter() for k in ('accepted', 'rejected')}
        self.proxies = {k: Counter() for k in ('accepted', 'rejected')}

    def __call__(self, row):
        if row.get('stage') == 'correlation_decision' and self.best:
            chosen = (self.valid_best or self.best)[1]
            ev = chosen['evidence']['evidence_v2']
            population = 'accepted' if row['decision'] == 'accept' else 'rejected'
            self.scores['all'].append(chosen['score'])
            self.scores[population].append(chosen['score'])
            for fact in ev['evidence']:
                self.composition[population][fact['family']+':'+fact['role']] += 1
            a, b = (self.index.alerts[x] for x in chosen['support_pair'])
            keys = self.proxies[population]
            keys['count'] += 1
            for field in ('src_ip', 'dst_ip', 'host', 'account', 'session', 'process', 'signature', 'rule_id'):
                keys['same_'+field] += int(getattr(a, field) is not None and getattr(a, field) == getattr(b, field))
            keys['cross_source'] += int(a.source_namespace != b.source_namespace)
            keys['confirmed_corroboration'] += int(chosen['values']['source'] > 0)
            keys['high_frequency_entity'] += int(any(r['hot'] for r in ev['entity_reliability']))
            keys['no_primary'] += int(not ev['primary_evidence'])
            non_time = [f for f in ev['evidence'] if f['family'] != 'TEMPORAL']
            keys['metadata_only'] += int(bool(non_time) and all(f['family'] == 'RULE_METADATA' for f in non_time))
            keys['network_continuity'] += int(ev['network_continuity_valid'])
            keys['attested_relation'] += int(bool(ev['relation_support']))
        super().__call__(row)

    def close(self):
        buckets = [self.bucket(s) for s in (0., .1, .2, .3, .4, .5, .6, .65, .7, .8, .9, 1.)]
        histograms = {k: Counter(self.bucket(s) for s in v) for k, v in self.scores.items()}
        report = {'population': 'one best valid member per candidate, best rejected if no valid member',
            'score_distribution': {k: {'count': len(v), 'quantiles': quantiles(v),
                'histogram': {b: histograms[k][b] for b in buckets}} for k, v in self.scores.items()},
            'evidence_composition': {k: dict(sorted(v.items())) for k, v in self.composition.items()},
            'evidence_proxies': {k: dict(sorted(v.items())) for k, v in self.proxies.items()},
            'proxy_semantics': 'selected-candidate-v2',
            'ground_truth_used': False, 'classification': 'observable evidence proxies, not pair precision/recall'}
        atomic_json(self.details/'development_audit.json', report)
        self.write({'stage': 'development_audit', 'summary': report}, essential=True)
        super().close()


def run(scene, version, destination):
    if scene not in {'russellmitchell', 'fox'} or version not in {'v3', 'v4'}:
        raise ValueError('development_split_violation')
    if scene == 'fox':
        from finalize_correlation_v4 import implementation_hashes, junit
        lock_path = ROOT/'outputs/correlation_v4/DEVELOPMENT_LOCK.json'
        if version != 'v4' or not lock_path.is_file() or not junit()['passed']:
            raise ValueError('fox_requires_verified_development_lock')
        lock = json.loads(lock_path.read_text(encoding='utf8'))
        if lock['implementation'] != implementation_hashes():
            raise ValueError('algorithm_changed_after_development_lock')
    destination = ROOT / destination
    if not destination.resolve().is_relative_to((ROOT/'outputs/correlation_v4').resolve()):
        raise ValueError('development_output_scope')
    destination.mkdir(parents=True, exist_ok=True)
    if (destination/'REAL_DATA_RESULT.json').exists():
        raise ValueError('immutable_receipt_exists')
    loaded = load_dataset(ROOT, scene_id=scene, config_version=version)
    if loaded.missing_files:
        raise ValueError('real_input_missing')
    atomic_json(destination/'recipe.json', dict(config_hash=loaded.config.config_hash,
        config_snapshot=loaded.config.snapshot, mapping_digest=loaded.config.mapping_digest,
        inputs=loaded.inputs, source_settings={k: v[1].snapshot() for k, v in loaded.sources.items()},
        dataset_role='primary_development' if scene == 'russellmitchell' else 'lightweight_validation',
        ground_truth_used=False))
    diagnostics.BoundedDiagnostics = DevelopmentObserver
    with truth_guard(ROOT):
        service = AnalysisService(ROOT, configs={version: loaded.config}, sources=loaded.sources,
            allowed_files=[v['path'] for v in loaded.inputs],
            progress=lambda row: print(json.dumps(row, ensure_ascii=False), flush=True))
        try:
            identity = service.create(loaded.request, background=False)
        finally:
            service.close()
        store = SnapshotStore(ROOT, identity)
        receipt = json.loads((store.domain/'run.json').read_text(encoding='utf8'))
        if receipt['status'] != 'completed':
            atomic_json(destination/'FAILED_RUN.json', receipt)
            raise ValueError('full_replay_failed:'+str(receipt['errors']))
        record, _, manifest = store.read_metadata()
        result = dict(analysis_id=identity, scene=scene, status=receipt['status'], is_complete=record.is_complete,
            algorithm_version=correlation_version(loaded.config), service_version=receipt['algorithm_version'],
            config_hash=record.config_hash, mapping_digest=record.mapping_digest, dataset_digest=record.dataset_digest,
            counts=receipt['counts'], runtime=receipt['runtime'], peak_memory_mb=record.metrics.peak_memory_mb,
            grounding=receipt['grounding'], snapshot_identity=manifest['execution']['snapshot_identity'],
            diagnostics_ref=record.diagnostics_ref, ground_truth_used=False, ai_used=False)
        atomic_json(destination/'REAL_DATA_RESULT.json', result)
        print(json.dumps(result), flush=True)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--scene', choices=['russellmitchell', 'fox'], required=True)
    parser.add_argument('--version', choices=['v3', 'v4'], required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    run(args.scene, args.version, args.destination)

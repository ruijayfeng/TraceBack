"""Immutable small-slice experiment. No GT, reselection or validation retry."""
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.adapters import AMinerAdapter, WazuhAdapter, AdapterSettings
from app.config import load_config
from app.services import bounded_diagnostics as diagnostics
from app.services.storage import atomic_json, file_digest, restore_config, SnapshotStore
from app.utils.stable_id import content_digest, utc_text
from app.models.base import resolve_pointer
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.correlation.candidates import candidate_diagnosis
from app.correlation.edges import run_correlation, correlation_version, peak_memory_mb
from app.chains.assembly import run_reconstruction
from app.incidents.triage import triage_singletons
from demo_support import truth_guard

OUTPUT = ROOT / 'outputs/correlation_v4_small'
SLICES = {'dev': 'russellmitchell_dev_small', 'validation': 'fox_validation_small'}


def quantiles(values):
    values = sorted(values)
    def q(f):
        if not values:
            return None
        p = (len(values)-1)*f
        lo = int(p)
        return values[lo] + (values[min(lo+1, len(values)-1)]-values[lo])*(p-lo)
    return {name: q(f) for name, f in [('p50', .5), ('p90', .9), ('p95', .95), ('p99', .99), ('max', 1)]}


def implementation():
    paths = sorted((ROOT/'backend/app').rglob('*.py')) + sorted((ROOT/'configs').rglob('*.yaml')) + [Path(__file__).resolve()]
    return {p.relative_to(ROOT).as_posix(): file_digest(p) for p in paths}


def slice_inputs(role):
    base = ROOT/'data/ait_ads/slices'/SLICES[role]
    manifest = json.loads((base/'slice_manifest.json').read_text(encoding='utf8'))
    paths = {s: base/'raw'/(s+'.json') for s in manifest['source_files']}
    for s, path in paths.items():
        if file_digest(path) != manifest['slice_sha256'][s]:
            raise ValueError('slice_hash_mismatch:'+s)
    return manifest, paths


def recipe(manifest, version):
    cfg = load_config(ROOT/f'configs/algorithm-{version}.yaml', deployment_override=ROOT/'configs/sources.yaml')
    snapshot = cfg.snapshot
    # Declared slice deployment metadata, never inferred from observations.
    snapshot['normalization']['source_timezones'].update({
        v['source_namespace']: manifest['timezone'] for v in manifest['adapter_settings'].values()})
    return restore_config(snapshot)


def complete_dev_exports(tag):
    """Finish reporting from completed snapshots, without rerunning algorithms."""
    dest = OUTPUT/tag
    result = json.loads((dest/'RESULT.json').read_text(encoding='utf8'))
    if result['role'] != 'dev':
        raise ValueError('report_repair_only_development')
    c = SnapshotStore(dest, result['correlation_analysis_id'])
    r = SnapshotStore(dest, result['reconstruction_analysis_id'])
    record, frequency, manifest = r.read_metadata(verify_files=False)
    # Earlier exporter attached triage after persistence; refresh only this new
    # experiment's manifest hashes, then fully verify the published snapshot.
    r.write_metadata(record, frequency, manifest['summary'])
    r.read_metadata()
    _, _, cm = c.read_metadata()
    from app.correlation.index import AlertIndex
    index = AlertIndex(list(c.read_records('alerts')), list(c.read_records('dedupe_groups')), list(c.read_records('entities')))
    incidents = list(r.read_records('incidents'))
    per_rep = cm['summary']['alert_correlation_diagnostics']
    atomic_json(dest/'singleton_diagnostics.json', {'definition':'one representative fact group; may contain deduplicated raw alerts',
        'items':[{'incident_id':i.incident_id, 'alert_ids':i.alert_ids, 'representative_id':index.owner[i.alert_ids[0]],
            **per_rep[index.owner[i.alert_ids[0]]]} for i in incidents if len({index.owner[a] for a in i.alert_ids})==1]})
    atomic_json(dest/'SEMANTIC_DIGEST.json', {'sha256':content_digest({
        'edges': sorted(e.canonical_json() for e in c.read_records('correlation_edges')),
        'incidents':sorted(i.canonical_json() for i in incidents),
        'chains':sorted(ch.canonical_json() for ch in r.read_records('attack_chains'))}), 'runtime_excluded':True})


def verify_dev_replay(tag):
    """Reverse-input candidate oracle and frozen-snapshot top-pair rescoring."""
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.correlation.candidates import generate_candidates
    from app.services.bounded_diagnostics import DiskCandidates
    dest = OUTPUT/tag
    result = json.loads((dest/'RESULT.json').read_text(encoding='utf8'))
    if result['role'] != 'dev':
        raise ValueError('replay_only_development')
    store = SnapshotStore(dest, result['correlation_analysis_id'])
    record, frequency, _ = store.read_metadata()
    cfg = restore_config(record.config_snapshot['algorithm'])
    settings = {k:AdapterSettings(**v) for k,v in record.config_snapshot['sources'].items()}
    alerts, groups, entities = [list(store.read_records(k)) for k in ('alerts','dedupe_groups','entities')]
    index = AlertIndex(list(reversed(alerts)), list(reversed(groups)), list(reversed(entities)))
    assert index.frequency_snapshot() == frequency
    scorer = CorrelationScorer(index, cfg, settings, record.config_hash)
    original = DiskCandidates(store.details/'candidate_batches', result['candidate_pair_count'])
    regenerated = generate_candidates(index, cfg, scorer)
    def digest(pairs):
        h = hashlib.sha256()
        for p in pairs:
            h.update(json.dumps(asdict(p), sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf8'))
            h.update(b'\n')
        return h.hexdigest()
    expected, actual = digest(original), digest(regenerated.pairs)
    assert expected == actual, 'reverse_input_candidate_digest_changed'
    checked = 0
    for population in ('accepted','rejected'):
        samples = json.loads((dest/f'top_{population}_pairs.json').read_text(encoding='utf8'))
        for sample in samples:
            row = sample['member']
            pair = scorer.score_pair(*row['support_pair'])
            assert pair.score == row['score'] and pair.valid == row['valid']
            assert pair.diagnostics == row['evidence']
            assert [r.model_dump(mode='json') for r in pair.reasons] == row['reasons']
            scorer.breakdown(pair)
            checked += 1
    reconstructed = SnapshotStore(dest, result['reconstruction_analysis_id'])
    reconstructed.read_metadata()
    reconstructed.validate_reconstruction()
    atomic_json(dest/'REPRODUCIBILITY.json', {'candidate_order_digest':actual,
        'reverse_input_all_candidates_equal':True, 'frozen_snapshot_sample_count':checked,
        'frozen_snapshot_scores_reasons_evidence_equal':True, 'snapshot_grounding_verified':True,
        'no_second_full_scoring_run':True})
    print(json.dumps({'replay':tag,'pairs':len(regenerated.pairs),'samples':checked}), flush=True)


class SmallObserver(diagnostics.BoundedDiagnostics):
    def __init__(self, *args):
        super().__init__(*args)
        self.scores = []
        self.tops = {'accepted': [], 'rejected': []}
        self.channels, self.relations, self.accepted_relations = Counter(), Counter(), Counter()
        self.stage_outcomes, self.overlays, self.reasons = Counter(), Counter(), Counter()
        self.audit = Counter()
        self.missing = Counter()

    def __call__(self, row):
        if row.get('stage') == 'candidate':
            self.channels.update(row['channels'])
        if row.get('stage') == 'correlation_decision' and self.best:
            chosen = (self.valid_best or self.best)[1]
            ev = chosen['evidence']['evidence_v2']
            self.scores.append(chosen['score'])
            accepted = row['decision'] == 'accept'
            key = 'accepted' if accepted else 'rejected'
            rels = ev['relation_support'] or ['unresolved_undirected']
            self.relations.update(rels)
            if accepted:
                self.accepted_relations.update(rels)
            outcome = ('F_guard_rejected' if ev['decision'] == 'REJECT_GUARD' else
                'C_insufficient_evidence' if not ev['evidence_gate_passed'] else
                'D_below_threshold' if not accepted else 'E_formal_edge')
            self.stage_outcomes[outcome] += 1
            self.reasons.update(chosen['rejection_codes'])
            self.reasons[ev['gate_reason']] += int(not accepted)
            self.overlays['B_no_directional_relation'] += int(not ev['relation_support'])
            non_time = [f for f in ev['evidence'] if f['family'] != 'TEMPORAL']
            self.overlays['G_metadata_only_rejected'] += int(not accepted and bool(non_time) and all(f['family']=='RULE_METADATA' for f in non_time))
            self.overlays['H_high_frequency_only_rejected'] += int(not accepted and bool(ev['entity_reliability']) and
                all(f['hot'] for f in ev['entity_reliability']) and not ev['primary_evidence'])
            self.missing['pairs_with_unavailable'] += int(bool(ev['unavailable_evidence']))
            self.missing['gate_passed_with_unavailable'] += int(ev['evidence_gate_passed'] and bool(ev['unavailable_evidence']))
            self.missing['available_mismatched_pairs'] += int(bool(ev['mismatched_evidence']))
            self.audit['selected_pairs'] += 1
            self.audit['duplicate_fact_key'] += len(ev['evidence'])-len({f['fact_key'] for f in ev['evidence']})
            ids = [eid for f in ev['evidence'] for eid in f['entity_ids']]
            self.audit['reused_entity_fact'] += len(ids)-len(set(ids))
            for fact in ev['evidence']:
                for ref in fact['evidence_refs']:
                    if ref['alert_id'] not in chosen['support_pair']:
                        raise ValueError('evidence_pointer_outside_support_pair')
                    resolve_pointer(self.index.alerts[ref['alert_id']].raw_alert, ref['pointer'])
                    self.audit['resolved_pointers'] += 1
            sample = {'candidate': self.current, 'decision': row, 'member': chosen}
            self.tops[key].append(sample)
            self.tops[key].sort(key=lambda s: (-s['member']['score'], *s['member']['support_pair']))
            del self.tops[key][50:]
        super().__call__(row)

    def close(self):
        histogram = {f'{i/10:.1f}–{(i+1)/10:.1f}': 0 for i in range(10)}
        for s in self.scores:
            i = min(int(s*10), 9)
            histogram[f'{i/10:.1f}–{(i+1)/10:.1f}'] += 1
        for key, samples in self.tops.items():
            for sample in samples:
                sample['alerts'] = [self.index.alerts[i].model_dump(mode='json') for i in sample['member']['support_pair']]
            # Internal ranking/support keys are tuples. Convert only the audit
            # transport, leaving candidate and scoring identities untouched.
            atomic_json(self.details/f'top_{key}_pairs.json', json.loads(json.dumps(samples, ensure_ascii=False)))
        report = dict(score_distribution={'population': 'best valid full member pair, else best rejected member',
            'count': len(self.scores), 'histogram': histogram, **quantiles(self.scores)},
            candidate_family_distribution=dict(self.channels), relation_candidate_distribution=dict(self.relations),
            relation_accepted_distribution=dict(self.accepted_relations), stage_outcomes=dict(self.stage_outcomes),
            overlays=dict(self.overlays), rejection_distribution=dict(self.reasons), evidence_audit=dict(self.audit),
            missing_field_diagnostics=dict(self.missing))
        atomic_json(self.details/'small_audit.json', report)
        super().close()


def run(role, version, tag):
    if role == 'validation':
        if version != 'v4' or tag != 'validation':
            raise ValueError('validation_requires_frozen_v4')
        freeze = json.loads((OUTPUT/'FREEZE_MANIFEST.json').read_text(encoding='utf8'))
        if not freeze['CORRELATION_V4_FROZEN'] or freeze['implementation'] != implementation():
            raise ValueError('freeze_integrity_failed')
    dest = OUTPUT/tag
    dest.mkdir(parents=True, exist_ok=False)  # A started validation can never retry.
    atomic_json(dest/'STARTED.json', {'role': role, 'version': version, 'formal_run_number': 1})
    manifest, paths = slice_inputs(role)
    cfg = recipe(manifest, version)
    if role == 'validation':
        # Same algorithm recipe; only declared source deployment/timezone differs.
        frozen = freeze['algorithm_snapshot']
        snap = cfg.snapshot
        for data in (frozen, snap):
            data['normalization']['source_timezones'] = {}
        if snap != frozen or cfg.mapping_digest != freeze['mapping_digest']:
            raise ValueError('validation_recipe_changed')
    settings = {v['source_namespace']: AdapterSettings(**v) for v in manifest['adapter_settings'].values()}
    atomic_json(dest/'recipe.json', {'algorithm_snapshot': cfg.snapshot, 'source_settings': manifest['adapter_settings'],
        'config_hash': content_digest({'algorithm': cfg.snapshot, 'sources': {k:v.snapshot() for k,v in sorted(settings.items())}}),
        'mapping_digest': cfg.mapping_digest, 'slice_manifest_sha256': file_digest(paths['aminer'].parents[1]/'slice_manifest.json'),
        'slice_sha256': manifest['slice_sha256'], 'source_files': manifest['source_files']})
    started = time.perf_counter()
    before = implementation()
    with truth_guard(ROOT):
        alerts, raw_counts = {}, {}
        t = time.perf_counter()
        for source, path in sorted(paths.items()):
            adapter = (AMinerAdapter if source=='aminer' else WazuhAdapter)(cfg, settings[manifest['adapter_settings'][source]['source_namespace']])
            batch = adapter.read_file(path)
            if batch.rejected or batch.input_count != manifest['raw_counts'][source]:
                raise ValueError('slice_adapter_count_mismatch')
            raw_counts[source] = batch.input_count
            for a in batch.alerts:
                if not manifest['start_timestamp'] <= utc_text(a.timestamp) <= manifest['end_timestamp']:
                    raise ValueError('out_of_slice_time')
                alerts[a.alert_id] = a
        timings = {'adapter_seconds': time.perf_counter()-t}
        alerts = [alerts[k] for k in sorted(alerts)]
        if len(alerts) != manifest['canonical_alert_count'] or content_digest(sorted([a.alert_id,a.raw_fingerprint] for a in alerts)) != manifest['canonical_identity_sha256']:
            raise ValueError('slice_canonical_identity_changed')
        print(json.dumps({'stage':'adapters', 'count':len(alerts)}), flush=True)
        t = time.perf_counter()
        dedupe = deduplicate(alerts, cfg, settings)
        if not dedupe.is_complete:
            raise ValueError('dedupe_incomplete')
        timings['dedupe_seconds'] = time.perf_counter()-t
        t = time.perf_counter()
        extracted = extract_entities(alerts, settings)
        timings['entity_seconds'] = time.perf_counter()-t
        alerts, entities = extracted.alerts, extracted.entities
        del extracted, batch
        diagnostics.BoundedDiagnostics = SmallObserver
        def progress(row):
            print(json.dumps(row, ensure_ascii=False), flush=True)
        def candidate_reports(reports):
            for name, data in reports.items():
                atomic_json(dest/(name+'.json'), data)
        with candidate_diagnosis(candidate_reports):
            correlation = run_correlation(alerts, dedupe.groups, entities, cfg, settings,
                output_root=dest, progress=progress)
        if not correlation.record.is_complete:
            raise ValueError('correlation_incomplete')
        store = SnapshotStore(dest, correlation.record.analysis_id)
        reconstruction = run_reconstruction(alerts, dedupe.groups, entities, correlation.edges, cfg, settings,
            upstream_record=correlation.record, output_root=dest, progress=progress)
        from app.correlation.index import AlertIndex
        index = AlertIndex(alerts, dedupe.groups, entities)
        reconstruction.incidents = triage_singletons(reconstruction.incidents, index, cfg, correlation.summary,
            search_complete=correlation.record.is_complete)
        reconstructed_store = SnapshotStore(dest, reconstruction.record.analysis_id)
        record, frequency, stored_manifest = reconstructed_store.read_metadata()
        reconstructed_store.write_records('incidents', reconstruction.incidents)
        reconstructed_store.write_metadata(record, frequency, stored_manifest['summary'])
        audit = json.loads((store.details/'small_audit.json').read_text(encoding='utf8'))
        report = dict(dataset=SLICES[role], role=role, algorithm_version=correlation_version(cfg),
            config_hash=correlation.record.config_hash, mapping_digest=cfg.mapping_digest,
            dataset_digest=correlation.record.dataset_digest, canonical_alert_count=len(alerts), raw_counts=raw_counts,
            start_timestamp=manifest['start_timestamp'], end_timestamp=manifest['end_timestamp'],
            representative_count=index.N, candidate_pair_count=correlation.record.metrics.candidate_pair_count,
            **{k:v for k,v in reconstruction.summary.items() if k not in {'canonical_alert_count','representative_count','grounding'}},
            grounding=reconstruction.grounding.json_data(), **audit, is_complete=correlation.record.is_complete,
            correlation_analysis_id=correlation.record.analysis_id, reconstruction_analysis_id=reconstruction.record.analysis_id,
            candidate_summary={k:correlation.summary[k] for k in ('potential_pair_stats','candidate_admission_stats',
                'policy_pruned_count','resource_truncated_count','admitted_candidate_count','scored_candidate_count')},
            runtime={**timings, **{k:v for k,v in correlation.summary.items() if k.endswith('_seconds')},
                'incident_build_seconds': reconstruction.record.metrics.clustering_runtime_seconds,
                'chain_seconds': reconstruction.record.metrics.chain_runtime_seconds, 'total_seconds':time.perf_counter()-started},
            peak_memory_mb=peak_memory_mb(), ground_truth_used=False)
        atomic_json(dest/'RESULT.json', report)
        for name in ('top_accepted_pairs', 'top_rejected_pairs'):
            atomic_json(dest/(name+'.json'), json.loads((store.details/(name+'.json')).read_text(encoding='utf8')))
        atomic_json(dest/'score_distribution.json', audit['score_distribution'])
        atomic_json(dest/'relation_distribution.json', {k:v for k,v in audit.items() if k.startswith('relation_')})
        atomic_json(dest/'rejection_distribution.json', {'primary':audit['stage_outcomes'], 'overlays':audit['overlays'], 'reasons':audit['rejection_distribution']})
        theoretical = index.N*(index.N-1)//2
        atomic_json(dest/'candidate_stats.json', {'representatives':index.N, 'theoretical_pair_count':theoretical,
            'generated_candidate_pair_count': report['candidate_pair_count'],
            'candidate_reduction_ratio':1-report['candidate_pair_count']/theoretical if theoretical else None,
            'A_not_candidate':theoretical-report['candidate_pair_count'], 'candidate_family_distribution':dict(audit['candidate_family_distribution']),
            **report['candidate_summary'], 'A_is_not_measured_recall': True})
        per_rep = correlation.summary['alert_correlation_diagnostics']
        atomic_json(dest/'singleton_diagnostics.json', {'definition':'one representative fact group; may contain deduplicated raw alerts',
            'items':[{'incident_id':i.incident_id, 'alert_ids':i.alert_ids, 'representative_id':index.owner[i.alert_ids[0]],
                **per_rep[index.owner[i.alert_ids[0]]]} for i in reconstruction.incidents if len({index.owner[a] for a in i.alert_ids})==1]})
        semantic = {'edges': sorted(e.canonical_json() for e in correlation.edges),
            'incidents':sorted(i.canonical_json() for i in reconstruction.incidents), 'chains':sorted(c.canonical_json() for c in reconstruction.chains)}
        atomic_json(dest/'SEMANTIC_DIGEST.json', {'sha256':content_digest(semantic), 'runtime_excluded':True})
    if before != implementation():
        raise ValueError('implementation_changed_during_run')
    slice_inputs(role)
    print(json.dumps({'completed':tag, 'candidates':report['candidate_pair_count'], 'edges':report['correlation_edge_count'],
        'scores':report['score_distribution']}), flush=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=SLICES, required=True)
    parser.add_argument('--version', choices=['v3','v4'], required=True)
    parser.add_argument('--tag', required=True)
    args = parser.parse_args()
    if '/' in args.tag or '\\' in args.tag or args.tag in {'.','..'}:
        raise ValueError('invalid_tag')
    run(args.role, args.version, args.tag)

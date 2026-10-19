"""Read-only frozen-v4 compatibility diagnostics; stops before clustering/chain.

Uses the accepted Step 2 snapshot, production dedupe and run_correlation, with
the production bounded execution context. Only Top 100 and aggregate reports
survive; disk candidate state is temporary. No scoring formula is implemented.
"""
from __future__ import annotations

import argparse
from array import array
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import heapq
import json
from pathlib import Path
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.adapters.cptc import load_cptc_dataset, read_cptc_file
from app.config import load_config
from app.correlation.edges import correlation_version, run_correlation, peak_memory_mb
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import deduplicate
from app.models.base import resolve_pointer
from app.services.capacity import bounded_execution, IMPLEMENTATION_VERSION
from app.services.storage import SnapshotStore, atomic_json as _atomic_json, file_digest, restore_config
from app.utils.stable_id import content_digest, raw_fingerprint
from demo_support import truth_guard

OUT = ROOT / 'outputs/cptc_2018_step3a'
CUTS = (.20, .30, .40, .50, .60, .65, .70, .75)
THRESHOLDS = (.60, .65, .67, .68, .69, .70, .75)
FIELDS = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'flow_id',
          'domain', 'url', 'host', 'account', 'session', 'signature', 'rule_id', 'category',
          'alert_type', 'severity', 'sensor', 'source_namespace', 'network_namespace')


def atomic_json(path, value):
    # Production diagnostics include tuples; artifacts use plain JSON arrays.
    _atomic_json(path, json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False)))


def quantiles(values, levels):
    ordered = sorted(values)
    if not ordered:
        return {name: None for name in levels}
    result = {}
    for name, q in levels.items():
        pos = (len(ordered)-1)*q
        lo = int(pos)
        hi = min(lo+1, len(ordered)-1)
        result[name] = ordered[lo] + (ordered[hi]-ordered[lo])*(pos-lo)
    return result


def bucket(score):
    names = ('<0.20', '[0.20,0.30)', '[0.30,0.40)', '[0.40,0.50)', '[0.50,0.60)',
             '[0.60,0.65)', '[0.65,0.70)', '[0.70,0.75)', '>=0.75')
    return names[next((i for i, c in enumerate(CUTS) if score < c), len(CUTS))]


def protected_hashes():
    files = [*sorted((ROOT/'backend/app').rglob('*.py')), *sorted((ROOT/'configs').rglob('*.yaml')),
             ROOT/'AGENTS.md', *sorted((ROOT/'docs').glob('*.md')),
             ROOT/'data/cptc_2018/dataset.yaml', *sorted((ROOT/'data/cptc_2018/raw/suricata').glob('*.gz'))]
    return {p.relative_to(ROOT).as_posix(): file_digest(p) for p in files}


def available_commit_mb():
    if sys.platform != 'win32':
        return None
    import ctypes
    class Status(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong)] + [
            (k, ctypes.c_ulonglong) for k in ('total_phys', 'avail_phys', 'total_page', 'avail_page',
                                            'total_virtual', 'avail_virtual', 'extended')]
    value = Status()
    value.length = ctypes.sizeof(value)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(value)):
        raise OSError('GlobalMemoryStatusEx failed')
    return value.avail_page / 2**20


def recipe(config, settings):
    snapshot = {'algorithm': config.snapshot, 'sources': {k: s.snapshot() for k, s in sorted(settings.items())}}
    return dict(algorithm_version=correlation_version(config), frozen_base_config_hash=config.config_hash,
                runtime_config_hash=content_digest(snapshot), mapping_digest=config.mapping_digest,
                correlation_threshold=config.algorithm.score.correlation_threshold,
                cluster_threshold=config.algorithm.clustering.edge_threshold,
                execution_implementation=IMPLEMENTATION_VERSION,
                runtime_config_snapshot=snapshot, differences='sources deployment declaration only; algorithm snapshot identical')


def load_frozen_config():
    """The accepted recipe includes mapping content, not just algorithm-v4.yaml."""
    path = ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json'
    manifest = json.loads(path.read_text(encoding='utf8'))
    if not manifest['CORRELATION_V4_FROZEN']:
        raise ValueError('v4_not_frozen')
    config = restore_config(manifest['algorithm_snapshot'])
    if config.mapping_digest != manifest['mapping_digest'] or correlation_version(config) != manifest['algorithm_version']:
        raise ValueError('frozen_recipe_digest_mismatch')
    # Scoring/candidates/guards/config files are readonly and must still match.
    required = ('backend/app/correlation/', 'backend/app/dedup/', 'backend/app/models/', 'configs/algorithm', 'configs/mappings/')
    mismatches = {p: dict(frozen=h, current=file_digest(ROOT/p)) for p, h in manifest['implementation'].items()
                  if p.startswith(required) and file_digest(ROOT/p) != h}
    if mismatches:
        # Step 3A.1 may change execution structures in these shared modules.
        # The original frozen receipt remains immutable; only an exact,
        # independently tested execution receipt can explain these differences.
        receipt_path = ROOT/'outputs/cptc_2018_step3a_capacity/EXECUTION_EQUIVALENCE_RECEIPT.json'
        allowed = {'backend/app/correlation/index.py', 'backend/app/correlation/candidates.py',
                   'backend/app/dedup/grouping.py', 'backend/app/dedup/observation.py', 'backend/app/correlation/evidence.py'}
        if receipt_path.is_file() and set(mismatches) <= allowed:
            receipt = json.loads(receipt_path.read_text(encoding='utf8'))
            result_path = ROOT/'outputs/cptc_2018_step3a_capacity/equivalence_results.json'
            execution_files = (*sorted(allowed), 'backend/app/services/capacity.py', 'backend/app/services/storage.py')
            if (receipt.get('scope') == 'execution_only' and receipt.get('equivalence_status') == 'PASS'
                and receipt.get('frozen_receipt_sha256') == file_digest(path)
                and receipt.get('algorithm_version') == manifest['algorithm_version']
                and receipt.get('mapping_digest') == manifest['mapping_digest']
                and receipt.get('implementation') == mismatches
                and receipt.get('execution_hashes') == {p:file_digest(ROOT/p) for p in execution_files}
                and result_path.is_file() and receipt.get('equivalence_results_sha256') == file_digest(result_path)
                and json.loads(result_path.read_text(encoding='utf8')).get('status') == 'PASS'):
                mismatches = {}
    if mismatches:
        raise ValueError('frozen_correlation_implementation_changed:'+json.dumps(mismatches))
    return config, manifest, path


def field_value(alert, name, settings):
    if name == 'protocol':
        return alert.raw_alert.get('proto')
    if name == 'flow_id':
        return alert.raw_alert.get('flow_id')
    if name == 'network_namespace':
        return settings[alert.source_namespace].network_namespace
    return getattr(alert, name)


# These explain inspected production call paths, not new evidence rules.
PATHS = {
    'timestamp': ('all channel windows/ranking', 'time.distance; observation identity; network order', 'TEMPORAL'),
    'src_ip': ('scoped IP posting', 'entity.IP; topology.network_continuity; observation identity', 'ENTITY_IDENTITY / NETWORK_FLOW'),
    'dst_ip': ('scoped IP posting', 'entity.IP role factor; network continuity; target guards', 'ENTITY_IDENTITY / NETWORK_FLOW'),
    'src_port': ('no standalone posting', 'observation identity; network continuity', 'NETWORK_FLOW'),
    'dst_port': ('no standalone posting', 'observation identity; network continuity; target guards', 'NETWORK_FLOW'),
    'protocol': ('no standalone posting', 'raw /proto -> ObservationMatcher; network protocol agreement', 'NETWORK_FLOW prerequisite / duplicate identity'),
    'flow_id': ('no standalone posting; affects dedupe representatives', 'raw /flow_id -> event fingerprint; duplicate observation; independent flow prerequisite', 'NETWORK_FLOW prerequisite / duplicate identity'),
    'domain': ('DOMAIN entity posting', 'entity.DOMAIN', 'RESOURCE_CONTEXT'),
    'url': ('URL entity posting', 'entity.URL with specificity check', 'RESOURCE_CONTEXT'),
    'host': ('HOST entity posting', 'entity.HOST; target and relation guards', 'HOST_CONTEXT'),
    'account': ('ACCOUNT entity posting', 'entity.ACCOUNT with scope', 'ACCOUNT_CONTEXT'),
    'session': ('SESSION entity posting', 'entity.SESSION with scope; relations', 'ENTITY_IDENTITY'),
    'signature': ('semantic only for entity-free alerts', 'same-source metadata merged once', 'RULE_METADATA'),
    'rule_id': ('semantic only for entity-free alerts', 'same-source metadata merged once; dedupe rule', 'RULE_METADATA'),
    'category': ('effective window and semantic eligibility', 'metadata.detector_identity; v4 network behavior prerequisite', 'RULE_METADATA / NETWORK_FLOW prerequisite'),
    'alert_type': ('semantic only for entity-free alerts', 'inspected but excluded by v4 metadata_support_fields', 'no independent fact'),
    'severity': ('none', 'none; triage not run in Step 3A', 'none'),
    'sensor': ('source complement only with attested independence/context', 'same_sensor suppression; source independence', 'SOURCE_CONTEXT prerequisite'),
    'source_namespace': ('scope fallback; semantic same-source restriction', 'metadata comparison scope; independence; origin', 'scope constraint; no partition bonus'),
    'network_namespace': ('shared IP scope', 'event fingerprint scope; namespace guard', 'scope constraint; no partition bonus'),
}


class Observer:
    """Aggregates production diagnostics without altering any decision."""
    def __init__(self, directory):
        self.directory = directory
        self.index = None
        self.count, self.members = 0, 0
        self.scores = array('d')
        self.families, self.fact_counts, self.support, self.decisions = Counter(), Counter(), Counter(), Counter()
        self.dimension_states, self.network_reasons, self.thresholds = Counter(), Counter(), Counter()
        self.histogram = Counter({bucket(x): 0 for x in (0., .2, .3, .4, .5, .6, .65, .7, .75)})
        self.matrix, self.edge_matrix, self.channels, self.degree = Counter(), Counter(), Counter(), Counter()
        self.top, self.samples = [], {}
        self.current = None
        self.valid, self.observed = None, None
        self.digest = hashlib.sha256()

    def prepare_candidates(self, index, candidates):
        self.index, self.candidates = index, candidates
        counts = Counter()
        for candidate in candidates.pairs:
            a, b = candidate.support_key
            self.degree[a] += 1
            self.degree[b] += 1
            self.matrix[tuple(sorted((index.alerts[a].source_namespace, index.alerts[b].source_namespace)))] += 1
            counts.update(candidate.channels)
        self.channels = counts
        atomic_json(self.directory/'candidate_generation_checkpoint.json', dict(
            total_canonical_alerts=len(index.alerts), total_representatives=index.N,
            scheduled=len(candidates.pairs), admitted=candidates.admitted_count,
            resource_truncated=candidates.resource_truncated_count, policy_pruned=candidates.policy_pruned_count,
            potential_pair_stats=candidates.potential_pair_stats, candidate_admission_stats=candidates.candidate_admission_stats))

    def __call__(self, row):
        stage = row['stage']
        if stage == 'candidate':
            self.current, self.valid, self.observed = row, None, None
            self.digest.update(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()+b'\n')
        elif stage == 'member_score':
            self.members += 1
            a, b = row['support_pair']
            key = (-row['score'], self.index.alerts[a].timestamp, self.index.alerts[b].timestamp, a, b)
            if self.observed is None or key < self.observed[0]:
                self.observed = key, row
            if row['valid'] and (self.valid is None or key < self.valid[0]):
                self.valid = key, row
        elif stage == 'correlation_decision':
            selected = (self.valid or self.observed)[1]
            score = selected['score']
            evidence = selected['evidence']['evidence_v2']
            self.count += 1
            self.scores.append(score)
            self.histogram[bucket(score)] += 1
            self.families.update(evidence['evidence_families'])
            independent = len({f['fact_key'] for f in evidence['evidence']})
            self.fact_counts[str(independent) if independent < 3 else '3+'] += 1
            self.support['primary_evidence_'+str(min(3, len(evidence['primary_evidence'])))] += 1
            entity = any(f['entity_ids'] and f['family'] != 'NETWORK_FLOW' for f in evidence['evidence'])
            network = evidence['network_continuity_valid']
            relation = bool(evidence['relation_support'])
            metadata_only = not entity and not network and not relation
            self.support.update({'entity_supported': int(entity), 'network_supported': int(network),
                                 'relation_supported': int(relation), 'metadata_only': int(metadata_only),
                                 'metadata_only_ge_0.65': int(metadata_only and score >= .65),
                                 'metadata_only_accepted': int(metadata_only and row['decision'] == 'accept')})
            self.decisions[evidence['decision']] += 1
            self.network_reasons[evidence['network_diagnostic']] += 1
            for d in evidence['dimensions']:
                self.dimension_states[(d['dimension'], d['state'])] += 1
            for cut in THRESHOLDS:
                self.thresholds[str(cut)] += int(score >= cut)
            pair = tuple(row['support_key'])
            if row['decision'] == 'accept':
                self.edge_matrix[tuple(sorted(self.index.alerts[x].source_namespace for x in pair))] += 1
            audit = {'candidate': self.current, 'selected_member': selected, 'production_decision': row}
            item = (score, pair, audit)
            if len(self.top) < 100:
                heapq.heappush(self.top, item)
            elif item[:2] > self.top[0][:2]:
                heapq.heapreplace(self.top, item)
            a, b = (self.index.alerts[x] for x in selected['support_pair'])
            cases = {'complete_ip': all(x.src_ip and x.dst_ip for x in (a, b)),
                     'single_sided_ip': any(bool(x.src_ip) != bool(x.dst_ip) for x in (a, b)),
                     'no_domain': not a.domain and not b.domain,
                     'no_flow_evidence': not network, 'metadata_only': metadata_only,
                     'multiple_independent_facts': independent >= 3}
            for name, matches in cases.items():
                if matches and name not in self.samples:
                    self.samples[name] = audit
            self.digest.update(json.dumps({'score': score, 'evidence': evidence, 'decision': row},
                                          sort_keys=True, separators=(',', ':')).encode()+b'\n')

    def enrich(self, audit, scorer):
        selected = audit['selected_member']
        pair = selected['support_pair']
        scored = scorer.score_pair(*pair)
        if scored.score != selected['score']:
            raise ValueError('top_pair_recalculation_mismatch')
        alerts = []
        for aid in pair:
            a = self.index.alerts[aid]
            alerts.append({**{f: field_value(a, f, scorer.settings) for f in FIELDS},
                           'alert_id': aid, 'raw_fingerprint': a.raw_fingerprint,
                           'field_provenance': {k: v.model_dump() for k, v in a.field_provenance.items()}})
        refs = [r for f in selected['evidence']['evidence_v2']['evidence'] for r in f['evidence_refs']]
        refs += [r for reason in selected['reasons'] for r in reason['params'].get('raw_pointers', [])]
        refs += selected['evidence'].get('duplicate_features', {}).get('observation_identity', {}).get('evidence_refs', [])
        for ref in refs:
            if ref['alert_id'] not in pair or resolve_pointer(self.index.alerts[ref['alert_id']].raw_alert, ref['pointer']) is None:
                raise ValueError('untraceable_evidence_pointer')
        return {**audit, 'alerts': alerts,
                'shared_entities': [self.index.entities[e].model_dump(mode='json', exclude={'alert_ids'})
                                    for e in scored.entity_ids],
                'relation_candidate': [r.json_data() for r in scored.relations],
                'score_breakdown': scorer.breakdown(scored).model_dump(mode='json'),
                'final_score_unrounded': scored.score, 'threshold_result': scored.score >= scorer.algorithm.score.correlation_threshold,
                'evidence_pointer_count': len(refs), 'evidence_pointers_valid': True}

    def finish(self, result, config, settings):
        scorer = CorrelationScorer(self.index, config, settings, result.record.config_hash)
        top = [self.enrich(x[2], scorer) for x in sorted(self.top, key=lambda x: (-x[0], x[1]))]
        samples = {name: self.enrich(audit, scorer) for name, audit in sorted(self.samples.items())}
        for name in ('complete_ip', 'single_sided_ip', 'no_domain', 'no_flow_evidence', 'metadata_only', 'multiple_independent_facts'):
            samples.setdefault(name, {'status': 'NOT_OBSERVED_IN_SCORED_CANDIDATES'})
        atomic_json(self.directory/'top_100_candidate_pairs.json', top)
        atomic_json(self.directory/'missing_aware_samples.json', samples)
        original_degrees = [self.degree[self.index.owner[aid]] for aid in self.index.alerts]
        degree_levels = dict(min=0., p50=.5, p90=.9, p95=.95, p99=.99, max=1.)
        candidate_stats = dict(total_canonical_alerts=len(self.index.alerts), total_representatives=self.index.N,
            candidate_pairs_total=self.candidates.admitted_count, scheduled_candidate_pairs=len(self.candidates.pairs),
            scored_candidate_pairs=self.count, verified_member_pairs=self.members,
            candidate_pairs_per_alert=quantiles(original_degrees, degree_levels),
            candidate_pairs_per_representative=quantiles([self.degree[r] for r in self.index.representatives], degree_levels),
            zero_candidate_alerts=sum(n == 0 for n in original_degrees), candidate_bearing_alerts=sum(n > 0 for n in original_degrees),
            population='scheduled candidates; original alerts inherit their fact-group degree',
            candidate_source_counts=dict(self.channels), source_counts_overlap=True,
            resource_truncated_count=self.candidates.resource_truncated_count, policy_pruned_count=self.candidates.policy_pruned_count,
            potential_pair_stats=self.candidates.potential_pair_stats,
            candidate_admission_stats=self.candidates.candidate_admission_stats)
        atomic_json(self.directory/'candidate_stats.json', candidate_stats)
        namespaces = sorted(settings)
        def matrix_report(counts):
            return dict(namespaces=namespaces, same_partition=sum(v for (a, b), v in counts.items() if a == b),
                cross_partition=sum(v for (a, b), v in counts.items() if a != b),
                matrix={a: {b: counts[tuple(sorted((a, b)))] for b in namespaces} for a in namespaces},
                matrix_semantics='symmetric off-diagonal counts displayed twice; each unordered pair counted once in totals')
        atomic_json(self.directory/'candidate_partition_matrix.json', matrix_report(self.matrix))
        atomic_json(self.directory/'correlation_edge_stats.json', dict(count=len(result.edges), **matrix_report(self.edge_matrix)))
        atomic_json(self.directory/'evidence_stats.json', dict(family_frequency=dict(sorted(self.families.items())),
            independent_fact_counts={k: self.fact_counts[k] for k in ('0', '1', '2', '3+')},
            independent_fact_semantics='unique production fact_key per selected pair, includes TEMPORAL and one merged RULE_METADATA; not confirmed-independent sources',
            support_counts=dict(sorted(self.support.items())), decisions=dict(sorted(self.decisions.items())),
            dimension_states={dim: {st: self.dimension_states[(dim, st)] for st in ('AVAILABLE_MATCH', 'AVAILABLE_MISMATCH', 'UNAVAILABLE', 'NOT_APPLICABLE')}
                              for dim in sorted({x[0] for x in self.dimension_states})},
            network_diagnostic=dict(sorted(self.network_reasons.items()))))
        atomic_json(self.directory/'score_distribution.json', dict(count=self.count,
            population='production best valid complete member pair; best rejected complete member if none valid',
            quantiles=quantiles(self.scores, dict(min=0., p50=.5, p75=.75, p90=.9, p95=.95, p99=.99, max=1.)),
            bins=dict(self.histogram), at_least={str(c): self.thresholds[str(c)] for c in THRESHOLDS},
            thresholds_are_diagnostic_only=True, formal_threshold=config.algorithm.score.correlation_threshold))
        atomic_json(self.directory/'deterministic_statistics.json', dict(candidate_and_score_digest=self.digest.hexdigest(),
            count=self.count, full_repeat='not run; repeat tests and Top 100 exact-score recalculation recorded separately'))
        summary = {k: v for k, v in result.summary.items() if k not in ('alert_correlation_diagnostics', 'accepted_samples',
            'highest_rejected_samples', 'cross_source_samples', 'same_source_samples', 'correlation_v2')}
        atomic_json(self.directory/'production_summary.json', summary)
        return top


def verify_originals(top, snapshot_root, dataset):
    wanted = {a['alert_id']: a['raw_fingerprint'] for pair in top for a in pair['alerts']}
    locators = {}
    with gzip.open(snapshot_root/'source_provenance.jsonl.gz', 'rt', encoding='utf8') as handle:
        for line in handle:
            row = json.loads(line)
            if row['alert_id'] in wanted:
                locators[row['alert_id']] = row
    requests = {}
    for aid, row in locators.items():
        requests.setdefault(row['source_partition'], {})[row['record_ordinal']] = aid
    matched = set()
    for part, targets in requests.items():
        for record in read_cptc_file(dataset.paths[part]):
            if record.ordinal in targets:
                aid = targets[record.ordinal]
                if record.error or raw_fingerprint(record.eve) != wanted[aid]:
                    raise ValueError('top_pair_original_raw_mismatch')
                matched.add(aid)
    if matched != set(wanted):
        raise ValueError('top_pair_source_locator_missing')
    for pair in top:
        for a in pair['alerts']:
            a['original_source_locator'] = {k: v for k, v in locators[a['alert_id']].items() if k != 'export_wrapper'}
    return dict(top_pair_alerts=len(wanted), original_raw_records_verified=len(matched), all_passed=True)


def build_report(directory):
    """Render already completed artifacts, without restarting algorithms."""
    import xml.etree.ElementTree as ET
    def read(name, default=None):
        p = directory/name
        return json.loads(p.read_text(encoding='utf8')) if p.exists() else (default or {})
    result, frozen = read('result.json'), read('frozen_recipe.json')
    fields, candidates = read('field_coverage.json'), read('candidate_stats.json')
    evidence, scores = read('evidence_stats.json'), read('score_distribution.json')
    partitions, edges = read('candidate_partition_matrix.json'), read('correlation_edge_stats.json')
    performance, protected = read('performance.json'), read('protected_files_verification.json')
    if frozen.get('accepted_receipt'):
        cfg, accepted, receipt_path = load_frozen_config()
        checked_runtime = content_digest({'algorithm': cfg.snapshot, 'sources': frozen['runtime_config_snapshot']['sources']})
        atomic_json(directory/'frozen_recipe_verification.json', dict(
            algorithm_version_unchanged=correlation_version(cfg) == frozen['algorithm_version'],
            frozen_base_config_hash_unchanged=cfg.config_hash == frozen['frozen_base_config_hash'],
            runtime_config_hash_unchanged=checked_runtime == frozen['runtime_config_hash'],
            mapping_digest_unchanged=cfg.mapping_digest == frozen['mapping_digest'],
            receipt_unchanged=file_digest(receipt_path) == frozen['accepted_receipt_sha256'],
            correlation_threshold_unchanged=cfg.algorithm.score.correlation_threshold == frozen['correlation_threshold'],
            cluster_threshold_unchanged=cfg.algorithm.clustering.edge_threshold == frozen['cluster_threshold']))
    step2 = json.loads((ROOT/'outputs/cptc_2018_step2/run_a/summary.json').read_text(encoding='utf8'))
    atomic_json(directory/'dataset_scope.json', {k: step2[k] for k in ('counts', 'per_file', 'dataset_digest',
        'mapping_digest', 'time_range_utc', 'category_distribution', 'severity_distribution')})
    # The production entry point returns an incomplete receipt after MemoryError.
    # Keep that actual resource result ahead of any downstream empty-observer error.
    resource_error = performance.get('production_timings', {}).get('resource_error')
    if resource_error:
        checkpoint = read('resource_checkpoint.json')
        result.update(status='CPTC_STEP3A_EXECUTION_BLOCKED', full_scan_completed=False,
                      full_scan_status='FULL_SCAN_NOT_COMPLETED', step_3b_ready=False,
                      production_resource_error=resource_error,
                      failed_production_stage=checkpoint.get('stage'))
        if result.get('error') and result['error'] != resource_error:
            result.setdefault('diagnostic_followup_error', result['error'])
        if result.get('diagnostic_followup_error') == resource_error:
            result.pop('diagnostic_followup_error')
        result['error'] = resource_error
    if not result.get('full_scan_completed') and not (directory/'candidate_stats.json').exists():
        unavailable = dict(status='UNAVAILABLE_FULL_SCAN_NOT_COMPLETED', population='no completed candidate set',
                           reason=result.get('production_resource_error', result.get('error')))
        dedupe = read('dedupe_stats.json')
        atomic_json(directory/'candidate_stats.json', dict(**unavailable,
            total_canonical_alerts=result.get('loaded_alerts', fields.get('total')), total_representatives=dedupe.get('representatives'),
            candidate_pairs_total=None, scheduled_candidate_pairs=None, scored_candidate_pairs=result.get('scored_candidates', 0),
            candidate_pairs_per_alert=None, candidate_bearing_alerts=None, zero_candidate_alerts=None))
        atomic_json(directory/'candidate_partition_matrix.json', dict(**unavailable, same_partition=None, cross_partition=None, matrix={}))
        atomic_json(directory/'evidence_stats.json', dict(**unavailable, family_frequency=None, independent_fact_counts=None))
        atomic_json(directory/'score_distribution.json', dict(**unavailable, count=0, quantiles=None, bins=None, at_least=None))
        atomic_json(directory/'top_100_candidate_pairs.json', [])
        atomic_json(directory/'correlation_edge_stats.json', dict(**unavailable, count=None, same_partition=None, cross_partition=None))
        atomic_json(directory/'missing_aware_samples.json', dict(**unavailable, synthetic_tests_only=True))
        atomic_json(directory/'evidence_traceability.json', dict(**unavailable, top_pair_validation='NOT_RUN'))
        atomic_json(directory/'deterministic_statistics.json', dict(**unavailable, full_repeat='NOT_RUN',
            scope='synthetic production reorder/bounded equivalence tests only; no full dataset statistics digest'))
        candidates = read('candidate_stats.json')
        partitions, edges = read('candidate_partition_matrix.json'), read('correlation_edge_stats.json')
        evidence, scores = read('evidence_stats.json'), read('score_distribution.json')
    if not result.get('full_scan_completed'):
        unavailable = dict(status='UNAVAILABLE_FULL_SCAN_NOT_COMPLETED', reason=result.get('error'))
        atomic_json(directory/'evidence_traceability.json', dict(**unavailable, top_pair_validation='NOT_RUN'))
        atomic_json(directory/'deterministic_statistics.json', dict(**unavailable, full_repeat='NOT_RUN',
            scope='synthetic production reorder/bounded equivalence tests only; no full dataset statistics digest'))
        if not candidates.get('total_representatives'):
            candidates['total_representatives'] = read('dedupe_stats.json').get('representatives')
            atomic_json(directory/'candidate_stats.json', candidates)
        checkpoint = read('resource_checkpoint.json')
        performance.update(resource_guard_threshold_mb=512, resource_guard_triggered=checkpoint.get('resource_abort'),
            exact_minimum_available_commit_mb=None,
            resource_observation='guard observed available commit below 512 MiB; exact minimum was not recorded',
            candidate_pairs_total=None, batch_size=1024, input_stage_complete=result.get('loaded_alerts') == 331554)
        atomic_json(directory/'performance.json', performance)
    tests = {}
    for name in ('pytest_regression', 'pytest_targeted', 'pytest_report'):
        path = directory/(name+'.xml')
        if path.exists():
            suites = list(ET.parse(path).getroot().iter('testsuite'))
            tests[name] = {k: sum(int(s.attrib.get(k, 0)) for s in suites) for k in ('tests', 'failures', 'errors', 'skipped')}
            tests[name]['passed'] = tests[name]['tests'] > 0 and tests[name]['failures'] == tests[name]['errors'] == 0
    atomic_json(directory/'tests_summary.json', tests)
    ready = bool(result.get('step_3b_ready')) and protected.get('unchanged', False) and bool(tests) and all(t['passed'] for t in tests.values())
    result['step_3b_ready'] = ready
    atomic_json(directory/'result.json', result)
    for name in FIELDS:
        if name in fields.get('fields', {}):
            fields['fields'][name]['runtime_validation'] = 'FULL_PRODUCTION_CORRELATION_COMPLETED' if result.get('full_scan_completed') else 'FIELD_CENSUS_COMPLETE; FULL_PRODUCTION_CORRELATION_NOT_COMPLETED'
    if fields:
        atomic_json(directory/'field_coverage.json', fields)
    top = read('top_100_candidate_pairs.json', [])
    lines = ['# CPTC-2018 Step 3A — Frozen Correlation v4 Compatibility & Scoring Diagnostic', '',
             '## 1. Task Result', '', f"`{result.get('status')}`; `{result.get('full_scan_status')}`.", '',
             'Only Step 3A. No clustering, chain reconstruction, AI, GT, demo selection or final dataset freeze was run.', '',
             '## 2. Frozen Correlation v4', '', f"Algorithm: `{frozen.get('algorithm_version')}`.", '',
             f"Frozen base config_hash: `{frozen.get('frozen_base_config_hash')}`.", '',
             f"Accepted deployment config_hash: `{frozen.get('accepted_deployment_config_hash')}` from `{frozen.get('accepted_receipt')}` "
             f"(SHA-256 `{frozen.get('accepted_receipt_sha256')}`).", '',
             f"CPTC runtime config_hash: `{frozen.get('runtime_config_hash')}`.", '',
             f"Mapping digest: `{frozen.get('mapping_digest')}`. Correlation threshold `{frozen.get('correlation_threshold')}`; cluster threshold `{frozen.get('cluster_threshold')}`.", '',
             'The runtime algorithm subtree is byte-equivalent canonical JSON to the loaded frozen base recipe. Runtime hash also includes the unchanged Step 2 source declarations. '
             'Step 2 category/severity mappings have already produced the canonical values; they are not reapplied or changed by v4. '
             'The frozen v4 mapping digest describes the files actually loaded for correlation, independently of the Step 2 ingestion mapping digest.', '',
             f"Protected production/config/docs/raw files unchanged: `{protected.get('unchanged')}`.", '',
             '## 3. Dataset Scope', '',
             f"Canonical alerts loaded: {fields.get('total', result.get('loaded_alerts', 'unavailable'))}. All six partition files, no time/score-selected subset. "
             'UTC range 2018-11-03T13:30:00.239265Z — 2018-11-03T23:29:59.754529Z. Source namespaces cptc_2018.t1/t2/t5/t7/t8/t9; network namespace cptc_2018. '
             'Partition numbers are source declarations, not attack stages.', '',
             f"Canonical category distribution: {json.dumps(step2['category_distribution'])}. Unknown category is present but has no mapped behavior support.", '',
             '## 4. Field Compatibility', '',
             '| Field | Location | Exists % | Nonempty % | Production candidate path | Production scoring path | Evidence |',
             '|---|---|---:|---:|---|---|---|']
    for name, row in fields.get('fields', {}).items():
        lines.append(f"| {name} | {row['location']} | {row['exists_rate']*100:.6f} | {row['nonempty_rate']*100:.6f} | {row['candidate_reader']} | {row['score_reader']} | {row['evidence_family']} |")
    lines += ['', 'Existence measures declared canonical schema fields; flow/proto measure raw extension keys and network_namespace measures deployment settings. '
              'A nonempty value does not establish a positive contribution. Exact runtime dimension availability/match counts are in evidence_stats.json, '
              'candidate channels in candidate_stats.json, and actual unrounded values/family strengths and contributions in Top Pair and missing-aware samples.', '',
              '## 5. flow_id Compatibility', '',
              f"{json.dumps(fields.get('flow_id', {}), ensure_ascii=False)}", '',
              'Frozen Suricata /flow_id + /proto + network tuple + tx_id (or exact event time) form observation identity. '
              'Production dedupe/duplicate penalty consume identity; v4 network continuity requires distinct complete flow observations with equal protocol '
              'and valid endpoint/behavior context. flow_id equality is not a standalone primary fact or a scoring bonus. '
              'The synthetic same/different flow test proves an actual duplicate-penalty and observation-risk change. No COMPATIBILITY_GAP_FLOW_ID was found.', '',
              '## 6. Sensor / Data Quality', '', json.dumps(fields.get('sensor', {}), ensure_ascii=False), '',
              'Sensor is preserved exactly as Step 2 stored it, including null. No Splunk host is promoted to a device identity. '
              'Missing/constant sensor cannot confirm independence. Frozen source complement is zero without declared independent origin/context. '
              'IP scope and network observation continuity use the declared network_namespace, so missing sensor does not create a sensor candidate bucket '
              'or silently separate the six network partitions.', '',
              '## 7. Candidate Generation', '',
              f"Representatives: {candidates.get('total_representatives', 'unavailable')}. Admitted unique CandidatePair: {candidates.get('candidate_pairs_total', 'unavailable')}; "
              f"scheduled: {candidates.get('scheduled_candidate_pairs', 'unavailable')}; scored: {candidates.get('scored_candidate_pairs', result.get('scored_candidates', 'unavailable'))}.", '',
              f"Candidate-bearing original alerts: {candidates.get('candidate_bearing_alerts', 'unavailable')}; zero candidate: {candidates.get('zero_candidate_alerts', 'unavailable')}.", '',
              f"Per original alert degree: {json.dumps(candidates.get('candidate_pairs_per_alert', {}))}.", '',
              f"Actual channels (overlapping): {json.dumps(candidates.get('candidate_source_counts', {}))}.", '',
              f"Policy pruned: {candidates.get('policy_pruned_count', 'unavailable')}; resource truncated: {candidates.get('resource_truncated_count', 'unavailable')}.", '',
              'Potential pairs, admitted candidates and scheduled/scored candidates remain distinct. The report never represents global budget losses as local policy. '
              'Degrees and partition matrix describe scheduled candidates; if resource-truncated, full admitted degrees are unavailable and Step 3B is not ready.', '',
              '## 8. Cross-Partition Candidates', '',
              f"Same partition: {partitions.get('same_partition', 'unavailable')}; cross partition: {partitions.get('cross_partition', 'unavailable')}.", '',
              '| Partition | ' + ' | '.join(x.split('.')[-1] for x in partitions.get('namespaces', [])) + ' |',
              '|---|' + '---:|'*len(partitions.get('namespaces', []))]
    for ns, row in partitions.get('matrix', {}).items():
        lines.append('| '+ns.split('.')[-1]+' | '+' | '.join(str(row[x]) for x in partitions['namespaces'])+' |')
    lines += ['', 'Each off-diagonal pair is displayed twice in the symmetric matrix and counted once in cross-partition totals. '
              'Synthetic partition renaming retains identical scores; shared network scope permits an IP candidate across distinct source namespaces. '
              'Frozen same-source metadata matching remains source-scoped; this is a declared production rule, not a partition-derived bonus.', '',
              '## 9. Evidence Coverage', '',
              f"Family frequency: {json.dumps(evidence.get('family_frequency', {}))}.", '',
              f"Fact-key counts (0/1/2/3+): {json.dumps(evidence.get('independent_fact_counts', {}))}.", '',
              'These are unique production fact keys after endpoint/relation consumption. TEMPORAL is one supporting fact; '
              'signature/rule/category are merged into one RULE_METADATA fact. These counts are not independent detector counts '
              'or proof that repeated observations are independent: production duplicate_observation_risk still vetoes primary evidence admission.', '',
              f"Support and metadata-only counts: {json.dumps(evidence.get('support_counts', {}))}.", '',
              f"Production decisions: {json.dumps(evidence.get('decisions', {}))}.", '',
              f"Network continuity outcomes: {json.dumps(evidence.get('network_diagnostic', {}))}.", '',
              '## 10. Missing-Aware Scoring', '',
              ('Actual CPTC score breakdowns are UNAVAILABLE because production correlation did not complete. Synthetic tests validate missing-aware boundaries separately. '
               if not result.get('full_scan_completed') else '') +
              'When available, missing_aware_samples.json stores actual full breakdowns for observed complete-IP, absent-domain, absent-network-flow, '
              'metadata-only and multiple-fact cases. A case absent from actual CPTC candidates is explicitly NOT_OBSERVED_IN_SCORED_CANDIDATES. '
              'Synthetic regression separately validates single-sided IP and missing flow: UNAVAILABLE/NOT_APPLICABLE contributes no negative conflict. '
              'A present-but-incompatible endpoint/behavior context can correctly be AVAILABLE_MISMATCH. '
              'Canonical severity never supplies an association bonus. Frozen quality/mass arithmetic is validated through the production ScoreBreakdown model; '
              'this script does not implement or reweight a scoring formula.', '',
              '## 11. Score Distribution', '',
              json.dumps(scores, ensure_ascii=False), '',
              'All statistics use unrounded production scores. Diagnostic cutoffs 0.60/0.67/0.68/0.69 etc. do not admit edges. '
              'Only production threshold, primary evidence gate and guards determine formal acceptance.', '',
              '## 12. Top Pair Findings', '',
              f"{len(top)} highest-scoring candidates in top_100_candidate_pairs.json, including rejected candidates. "
              'Each contains representative and selected original-member IDs, timestamps/namespaces/network fields, signature/flow, shared entities, '
              'relations, actual evidence facts, score breakdown, threshold result and production guard/decision. ' +
              ('Top Pair/source-pointer auditing was NOT_RUN; there is no completed Top Pair set. '
               if not top else 'Original gzip record locators and raw fingerprint equality are verified in evidence_traceability.json. ') +
              'No accepted edge is inferred from score alone.', '',
              '## 13. CorrelationEdge Observation', '',
              f"Formal CorrelationEdge: {edges.get('count', 'unavailable')}; same partition: {edges.get('same_partition', 'unavailable')}; "
              f"cross partition: {edges.get('cross_partition', 'unavailable')}.", '',
              'Counts come from the real production edge admission path. No CPTC bonus, changed guard, category mapping or lower threshold.', '',
              '## 14. Incident Observation', '',
              'NOT_RUN. This task uses the existing correlation-only entry point; total/singleton/multi-alert/largest Incident are unavailable. '
              'No estimated Incident or ChainEdge counts are substituted.', '',
              '## 15. Performance', '',
              json.dumps(performance, ensure_ascii=False), '',
              f"Execution failure (if any): {result.get('error', 'none')}.", '',
              'Indexed production postings/blocked masks count dense potential without unbounded pair enumeration. '
              'SQLite candidate state and raw spill are temporary; candidate payloads are not duplicated into final outputs. '
              'Top 100, aggregate statistics and test artifacts are retained. An early diagnostic attempt was interrupted before candidate generation '
              'to bound the Top Pair serialization. The bare-YAML attempt was rejected for missing the accepted deployment mappings and is retained only '
              'under attempt_2_rejected_recipe; execution_formal.log identifies the official frozen-recipe run.', '',
              '## 16. Tests', '', json.dumps(tests, ensure_ascii=False), '',
              'Synthetic fixtures are only regression tests, not substitutes for CPTC input. Input-reorder and bounded/nonbounded tests compare '
              'candidate provenance, unrounded selected scores/evidence and decisions. ' +
              ('No actual Top 100 rescoring or full statistics digest/repeat was completed. ' if not top else
               'Top 100 was rescored exactly against the original production index; deterministic_statistics.json records the first full stream digest. ') +
              'A second complete dataset replay was not run.', '',
              'Full-suite historical failures, if present: test_d1_positive_scan::test_frozen_config_identity_and_thresholds and '
              'test_final_demo_selection::test_accepted_frozen_algorithm_and_mapping_are_unchanged compare normalization.py with the older freeze manifest. '
              'Step 2 already recorded the authorized normalization repair. This task changes neither that file nor the historical manifest; '
              'protected_files_before/protected_files_verification prove its entry/exit SHA-256 is identical.', '',
              '## 17. Files Changed', '',
              '- scripts/cptc_2018_step3a.py\n- backend/tests/test_cptc_correlation_compatibility.py\n- outputs/cptc_2018_step3a/**', '',
              '## 18. Compatibility Verdict', '', f"`{result.get('status')}`.", '',
              'A high score or small edge count alone is neither a compatibility defect nor dataset suitability evidence. '
              'Any incomplete run cannot certify full compatibility, even if synthetic tests pass.', '',
              '## 19. Step 3B Readiness', '', f"STEP_3B_READY = {'YES' if ready else 'NO'}", '',
              'Step 3B has not been executed.']
    (directory/'CPTC_CORRELATION_COMPATIBILITY_REPORT.md').write_text('\n'.join(lines)+'\n', encoding='utf8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUT)
    parser.add_argument('--report-only', action='store_true')
    args = parser.parse_args()
    directory = args.output.resolve()
    if not directory.is_relative_to(OUT.resolve()):
        raise ValueError('step3a_output_boundary')
    directory.mkdir(parents=True, exist_ok=True)
    if args.report_only:
        print(json.dumps(build_report(directory)), flush=True)
        return
    started = time.perf_counter()
    state = {'stage': 'input_validation', 'loaded_alerts': 0, 'resource_abort': False}
    stop = threading.Event()
    def monitor():
        tick = 0
        while not stop.wait(2):
            tick += 1
            commit = available_commit_mb()
            if commit is not None and commit < 512:
                state['resource_abort'] = True
            if tick % 22 == 0:
                row = dict(**state, elapsed_seconds=time.perf_counter()-started,
                           available_commit_mb=commit, peak_memory_mb=peak_memory_mb())
                print(json.dumps(row), flush=True)
                atomic_json(directory/'resource_checkpoint.json', row)
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    before = protected_hashes()
    atomic_json(directory/'protected_files_before.json', before)
    result, observer = None, Observer(directory)
    try:
        with truth_guard(ROOT), bounded_execution(directory/'execution_spill') as spill:
            def resource_check():
                if state['resource_abort']:
                    raise MemoryError('host_available_commit_below_512_MiB')
            spill.resource_check = resource_check
            dataset = load_cptc_dataset(ROOT)
            config, accepted, receipt_path = load_frozen_config()
            settings = dataset.source_settings
            frozen = recipe(config, settings)
            frozen.update(accepted_receipt=receipt_path.relative_to(ROOT).as_posix(),
                          accepted_receipt_sha256=file_digest(receipt_path),
                          accepted_deployment_config_hash=accepted['config_hash'])
            if frozen['correlation_threshold'] != .65 or frozen['cluster_threshold'] != .70:
                raise ValueError('unexpected_frozen_threshold')
            atomic_json(directory/'frozen_recipe.json', frozen)
            print(json.dumps({k: v for k, v in frozen.items() if k != 'runtime_config_snapshot'}), flush=True)
            snapshot_root = ROOT/'outputs/cptc_2018_step2/run_a'
            summary = json.loads((snapshot_root/'summary.json').read_text(encoding='utf8'))
            if summary['counts']['canonical_alerts'] != 331554 or summary['file_errors']:
                raise ValueError('step2_snapshot_not_accepted')
            store = SnapshotStore(snapshot_root, summary['snapshot_id'])
            alerts = spill.alerts()
            present, nonempty, unique, sensors, windows = Counter(), Counter(), set(), Counter(), {}
            origin = datetime(1970, 1, 1, tzinfo=timezone.utc)
            for alert in store.read_records('alerts', parquet=True):
                alerts.add(alert)
                state['loaded_alerts'] = len(alerts)
                for field in FIELDS:
                    value = field_value(alert, field, settings)
                    # Top-level schema existence is distinct from raw/deployment extension presence.
                    exists = field in type(alert).model_fields or value is not None
                    present[field] += int(exists)
                    nonempty[field] += int(value is not None and value != '')
                value = alert.raw_alert.get('flow_id')
                if value is not None:
                    unique.add(value)
                sensors[str(alert.sensor)] += 1
                stamp = (datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00'))-origin).total_seconds()
                for seconds in (900, 1800, 3600, 7200, 14400):
                    key = str(seconds)
                    windows.setdefault(key, Counter())[int(stamp//seconds)*seconds] += 1
                if len(alerts) % 50000 == 0:
                    print(json.dumps(dict(stage='canonical_loaded', count=len(alerts))), flush=True)
            alerts.sorted()
            digest = content_digest([[a.alert_id, a.raw_fingerprint] for a in alerts.values()])
            if len(alerts) != 331554 or digest != summary['dataset_digest']:
                raise ValueError('canonical_input_digest_mismatch')
            coverage = {f: dict(exists=present[f], nonempty=nonempty[f], nonempty_rate=nonempty[f]/len(alerts),
                exists_rate=present[f]/len(alerts), location='raw_alert' if f in ('flow_id', 'protocol') else 'deployment settings' if f=='network_namespace' else 'canonical',
                candidate_reader=PATHS[f][0], score_reader=PATHS[f][1], evidence_family=PATHS[f][2]) for f in FIELDS}
            atomic_json(directory/'field_coverage.json', dict(total=len(alerts), fields=coverage,
                flow_id=dict(coverage=nonempty['flow_id']/len(alerts), unique_count=len(unique), legal_path=True,
                    candidate_relevance='observation-aware dedupe determines representatives; no standalone flow index',
                    direct_weight=False, production_pointers=config.algorithm.duplicate.observation.event_pointers['suricata']),
                sensor=dict(values=dict(sensors), classification='DATA_QUALITY_LIMITATION',
                    implications='constant 0 does not prove device identity/independence; no standalone sensor candidates; network identity uses network namespace, not sensor; no sensor-based widening')))
            atomic_json(directory/'time_window_diagnostics.json', dict(anchor='UTC epoch aligned fixed continuous bins, [start,end); trailing empty intervals included',
                selection='input timestamps only; no rescoring or configuration change', windows={k:
                    [{'start': datetime.fromtimestamp(t, timezone.utc).isoformat(), 'alert_count': rows[t]}
                     for t in range(min(rows), max(rows)+int(k), int(k))] for k, rows in windows.items()}))
            entities = list(store.read_records('entities', parquet=True))
            state['stage'] = 'production_dedupe'
            dedupe = deduplicate(alerts.sequence(), config, settings)
            atomic_json(directory/'dedupe_stats.json', dict(groups=len(dedupe.groups), candidates=dedupe.candidate_count,
                verified_pairs=dedupe.verified_pair_count, is_complete=dedupe.is_complete,
                representatives=len(alerts)-sum(len(g.alert_ids)-1 for g in dedupe.groups)))
            if not dedupe.is_complete:
                raise MemoryError(dedupe.incomplete_reason)
            state['stage'] = 'production_candidate_generation'
            def progress(row):
                resource_check()
                state['stage'] = 'production_scoring'
                print(json.dumps(row), flush=True)
                atomic_json(directory/'progress.json', row)
            result = run_correlation(alerts.sequence(), dedupe.groups, entities, config, settings,
                                     diagnostic_sink=observer, progress=progress)
            if result.candidates is None:
                raise MemoryError(result.record.incomplete_reason)
            state['stage'] = 'aggregate_and_top_pair_audit'
            top = observer.finish(result, config, settings)
            trace = verify_originals(top, snapshot_root, dataset)
            atomic_json(directory/'top_100_candidate_pairs.json', top)
            atomic_json(directory/'evidence_traceability.json', trace)
            checked_config, checked_receipt, checked_path = load_frozen_config()
            frozen_after = recipe(checked_config, settings)
            frozen_after.update(accepted_receipt=checked_path.relative_to(ROOT).as_posix(),
                                accepted_receipt_sha256=file_digest(checked_path),
                                accepted_deployment_config_hash=checked_receipt['config_hash'])
            if frozen != frozen_after:
                raise ValueError('frozen_recipe_changed')
            verdict = 'CPTC_CORRELATION_COMPATIBILITY_ACCEPTED' if result.record.is_complete else 'CPTC_STEP3A_EXECUTION_BLOCKED'
            atomic_json(directory/'result.json', dict(status=verdict, full_scan_completed=result.record.is_complete,
                full_scan_status='COMPLETED' if result.record.is_complete else 'FULL_SCAN_NOT_COMPLETED',
                algorithm_record=result.record.model_dump(mode='json'), step_3b_ready=result.record.is_complete,
                incident_observation='NOT_RUN; correlation-only production entry point', chain_executed=False,
                ground_truth_used=False, traceability=trace))
    except Exception as exc:
        traceback.print_exc()
        resource = isinstance(exc, MemoryError)
        atomic_json(directory/'result.json', dict(status='CPTC_STEP3A_EXECUTION_BLOCKED' if resource else 'CPTC_CORRELATION_COMPATIBILITY_DEFECT',
            full_scan_completed=False, full_scan_status='FULL_SCAN_NOT_COMPLETED', stage=state['stage'],
            loaded_alerts=state['loaded_alerts'], scored_candidates=observer.count,
            error=str(exc), step_3b_ready=False, ground_truth_used=False))
    finally:
        stop.set()
        thread.join(5)
        after = protected_hashes()
        atomic_json(directory/'protected_files_verification.json', dict(unchanged=before == after,
            changed=[p for p in sorted(set(before)|set(after)) if before.get(p) != after.get(p)]))
        atomic_json(directory/'performance.json', dict(runtime_seconds=time.perf_counter()-started,
            peak_memory_mb=peak_memory_mb(), scored_candidates=observer.count,
            scored_candidates_per_second=observer.count/(time.perf_counter()-started),
            strategy='production capacity-v4.1 disk packed raw, blocked bitset indexed retrieval, SQLite candidate spill, bounded caches; production frozen global budget unchanged',
            production_timings=result.summary if result and not result.record.is_complete else
                {k: v for k, v in (result.summary if result else {}).items() if k.endswith('_seconds')}))
        build_report(directory)


if __name__ == '__main__':
    main()

"""Read-only replay of the accepted CPTC t5 candidate universe.

Calls the frozen generator and scorer unchanged. Only compact numeric score
rows are retained on disk; full payloads are expanded after global ranking.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import heapq
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.adapters.base import AdapterSettings
from app.correlation.candidates import generate_candidates
from app.correlation.edges import correlation_version, peak_memory_mb
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.models import CanonicalAlert, DedupeGroup, Entity
from app.services.capacity import bounded_execution
from app.services.storage import file_digest, restore_config
from app.utils.stable_id import content_digest
from cptc_2018_step3a import atomic_json, load_frozen_config
from demo_support import truth_guard

RUN = ROOT / 'outputs/cptc_2018_step3a_t5'
OUT = ROOT / 'outputs/cptc_top100_diagnostic'
INPUT = ROOT / 'data/cptc_2018/raw/suricata/suricata_alert_t5.json.gz'


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def log(stage, **data):
    print(json.dumps(dict(stage=stage, **data), ensure_ascii=False), flush=True)


def protected_hashes():
    paths = [*sorted((ROOT/'backend/app').rglob('*.py')),
             *sorted((ROOT/'configs').rglob('*.*')), ROOT/'AGENTS.md',
             *sorted((ROOT/'docs').glob('*.md')), ROOT/'data/cptc_2018/dataset.yaml', INPUT,
             *sorted(p for p in RUN.iterdir() if p.is_file())]
    return {p.relative_to(ROOT).as_posix(): file_digest(p) for p in paths if p.is_file()}


def frozen():
    saved = read_json(RUN/'recipe.json')
    config, receipt, path = load_frozen_config()
    restored = restore_config(saved['config_snapshot']['algorithm'])
    assert restored.snapshot == config.snapshot, 'saved_algorithm_differs_from_freeze'
    assert config.mapping_digest == saved['mapping_digest']
    assert correlation_version(config) == saved['algorithm_version']
    assert content_digest(saved['config_snapshot']) == saved['config_hash']
    settings = {k: AdapterSettings(**v) for k,v in saved['config_snapshot']['sources'].items()}
    assert list(settings) == ['cptc_2018.t5']
    manifest = read_json(RUN/'manifest.json')
    assert manifest['is_complete'] and manifest['production_input'] == INPUT.relative_to(ROOT).as_posix()
    assert file_digest(INPUT) == manifest['raw_sha256']
    for name, digest in manifest['files'].items():
        assert file_digest(RUN/name) == digest, 'original_artifact_changed:'+name
    return config, settings, saved


def records(name, model):
    import duckdb
    db = duckdb.connect(':memory:')
    db.execute("SET memory_limit='256MB'")
    db.execute('SET threads=1')
    try:
        cursor = db.execute('SELECT payload FROM read_parquet(?) ORDER BY object_id', [str(RUN/(name+'.parquet'))])
        for batch in iter(lambda: cursor.fetchmany(128), []):
            for (payload,) in batch:
                yield model.model_validate_json(payload)
    finally:
        db.close()


@contextmanager
def saved_index(config, settings, directory):
    with bounded_execution(directory) as spill:
        spill.progress = lambda row: log(**row)
        alerts = spill.alerts()
        for count, alert in enumerate(records('alerts', CanonicalAlert), 1):
            alerts.add(alert)
            if count % 10000 == 0:
                log('load_snapshot', alerts=count)
        groups = list(records('dedupe_groups', DedupeGroup))
        entities = list(records('entities', Entity))
        index = AlertIndex(alerts.sequence(), groups, entities)
        scorer = CorrelationScorer(index, config, settings, read_json(RUN/'recipe.json')['config_hash'])
        yield index, scorer


def rank_key(score, a, b):
    return (-score, a, b)


class TopK:
    """The heap root is the worst retained score / lexical tie, never the best."""
    def __init__(self, k=100):
        self.k, self.heap = k, []

    def add(self, score, a, b, payload):
        # IDs have fixed ASCII format; negate character codes to reverse ties.
        item = (score, tuple(-ord(c) for c in a), tuple(-ord(c) for c in b), a, b, payload)
        if len(self.heap) < self.k:
            heapq.heappush(self.heap, item)
        elif item[:3] > self.heap[0][:3]:
            heapq.heapreplace(self.heap, item)

    def rows(self):
        return [dict(score=x[0], alert_a_id=x[3], alert_b_id=x[4], **x[5])
                for x in sorted(self.heap, key=lambda x: rank_key(x[0], x[3], x[4]))]


def create_scores(path, ids):
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=OFF')
    db.execute('PRAGMA synchronous=OFF')
    db.execute('PRAGMA temp_store=FILE')
    db.execute('PRAGMA cache_size=-8192')
    db.executescript('''
      CREATE TABLE alerts(i INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE);
      CREATE TABLE members(a INT,b INT,ra INT,rb INT,score REAL,valid INT);
      CREATE TABLE candidates(ra INT,rb INT,a INT,b INT,score REAL,valid INT);
    ''')
    db.executemany('INSERT INTO alerts VALUES (?,?)', enumerate(ids))
    db.commit()
    return db


def interval(score):
    if score == 1.:
        return '{1.00}'
    bounds = (0., .1, .2, .3, .4, .5, .6, .65, .7, .8, .9, 1.)
    return next(f'[{a:.2f},{b:.2f})' for a,b in zip(bounds,bounds[1:]) if a <= score < b)


def replay():
    OUT.mkdir(parents=True, exist_ok=True)
    if (OUT/'replay_complete.json').exists():
        raise ValueError('replay_already_complete_use_expand')
    started = time.perf_counter()
    before = protected_hashes()
    atomic_json(OUT/'protected_before.json', before)
    config, settings, recipe = frozen()
    baseline = read_json(RUN/'experiment_summary.json')['correlation']
    log('frozen_verified', algorithm_version=recipe['algorithm_version'], config_hash=recipe['config_hash'])
    atomic_json(OUT/'FROZEN_RECIPE.json', recipe)
    # No production output directory is passed; no original snapshot is written.
    with truth_guard(ROOT), saved_index(config, settings, OUT/'replay_spill') as (index, scorer):
        ids = sorted(index.alerts)
        assert content_digest([[aid,index.alerts[aid].raw_fingerprint] for aid in ids]) == recipe['dataset_digest']
        assert index.N == baseline['representative_alert_count']
        # Verify all previously persisted Top20 individual scoring results first.
        samples = read_json(RUN/'evidence_samples.json')['top20_pairs']
        for row in samples:
            actual = scorer.score_pair(*row['selected_member']['support_pair'])
            assert actual.score == row['final_score_unrounded'], 'old_top20_score_mismatch'
        log('old_top20_recomputed', count=len(samples))
        log('candidate_generation_start')
        candidates = generate_candidates(index, config, scorer)
        checkpoint = read_json(RUN/'candidate_generation_checkpoint.json')
        assert len(candidates.pairs) == checkpoint['scheduled']
        assert candidates.admitted_count == checkpoint['admitted']
        assert candidates.potential_pair_stats == checkpoint['potential_pair_stats']
        assert candidates.policy_pruned_count == checkpoint['policy_pruned']
        assert candidates.resource_truncated_count == 0
        atomic_json(OUT/'candidate_replay_verification.json', dict(status='PASS', **checkpoint,
            original_pair_identity_digest_available=False,
            identity_verification='Same immutable CanonicalAlerts/dedupe/entities, frozen code and config; deterministic generator replay. Original run retained no full identity stream or candidate digest.',
            windows=config.algorithm.candidate.model_dump(mode='json')))
        log('candidate_generation_complete', candidates=len(candidates.pairs), elapsed_seconds=time.perf_counter()-started)
        db = create_scores(OUT/'compact_scores.sqlite', ids)
        numbers = {aid:i for i,aid in enumerate(ids)}
        candidate_top, member_top = TopK(), TopK()
        member_rows, candidate_rows = [], []
        member_hist, candidate_hist, rejections = Counter(), Counter(), Counter()
        decision_counts, network_reasons = Counter(), Counter()
        digest = hashlib.sha256()
        member_count = accepted_count = gate_members = 0
        for n, candidate in enumerate(candidates.pairs, 1):
            ra, rb = candidate.support_key
            digest.update((ra+' '+rb+'\n').encode('ascii'))
            winner = observed = None
            candidate_json = None
            for a in index.groups[ra]:
                for b in index.groups[rb]:
                    scored = scorer.score_pair(a,b)
                    member_count += 1
                    audit = scored.diagnostics['evidence_v2']
                    gate_members += audit['evidence_gate_passed']
                    tie = (-scored.score,index.alerts[a].timestamp,index.alerts[b].timestamp,a,b)
                    if observed is None or tie < observed[0]:
                        observed = (tie,scored)
                    if scored.valid and (winner is None or tie < winner[0]):
                        winner = (tie,scored)
                    member_hist[interval(scored.score)] += 1
                    member_rows.append((numbers[a],numbers[b],numbers[ra],numbers[rb],scored.score,int(scored.valid)))
                    ma, mb = sorted((a,b))
                    if len(member_top.heap) < 100 or rank_key(scored.score,ma,mb) < rank_key(member_top.heap[0][0],member_top.heap[0][3],member_top.heap[0][4]):
                        if candidate_json is None:
                            candidate_json = dict(support_key=[ra,rb],channels=list(candidate.channels),
                                evidence=[e.json_data() for e in candidate.evidence],priority=candidate.priority)
                        member_top.add(scored.score,ma,mb,dict(support_pair=[a,b], candidate=candidate_json))
            selected = (winner or observed)[1]
            accepted = winner is not None and selected.score >= config.algorithm.score.correlation_threshold
            accepted_count += accepted
            member_candidate = [selected.source_member_id,selected.target_member_id]
            candidate_rows.append((numbers[ra],numbers[rb],*[numbers[x] for x in member_candidate],selected.score,int(winner is not None)))
            candidate_hist[interval(selected.score) if winner else 'no_valid_member_pair'] += 1
            rejections['accept' if accepted else 'below_correlation_threshold' if winner else 'no_valid_member_pair'] += 1
            decision_counts[selected.diagnostics['evidence_v2']['decision']] += 1
            network_reasons[selected.diagnostics['evidence_v2']['network_diagnostic']] += 1
            if len(candidate_top.heap) < 100 or rank_key(selected.score,ra,rb) < rank_key(candidate_top.heap[0][0],candidate_top.heap[0][3],candidate_top.heap[0][4]):
                if candidate_json is None:
                    candidate_json = dict(support_key=[ra,rb],channels=list(candidate.channels),
                        evidence=[e.json_data() for e in candidate.evidence],priority=candidate.priority)
                candidate_top.add(selected.score,ra,rb,dict(support_pair=member_candidate,
                    candidate=candidate_json,production_valid=winner is not None,formal_edge_admitted=accepted))
            if n % 5000 == 0:
                db.executemany('INSERT INTO members VALUES (?,?,?,?,?,?)',member_rows)
                db.executemany('INSERT INTO candidates VALUES (?,?,?,?,?,?)',candidate_rows)
                db.commit()
                member_rows.clear(); candidate_rows.clear()
            if n % 10000 == 0:
                atomic_json(OUT/'progress.json', dict(stage='scoring',scored_candidates=n,
                    scored_members=member_count,total_candidates=len(candidates.pairs),
                    elapsed_seconds=time.perf_counter()-started,peak_rss_mib=peak_memory_mb()))
                log('scoring',candidates=n,members=member_count,elapsed_seconds=time.perf_counter()-started)
        db.executemany('INSERT INTO members VALUES (?,?,?,?,?,?)',member_rows)
        db.executemany('INSERT INTO candidates VALUES (?,?,?,?,?,?)',candidate_rows)
        db.commit(); db.close()
        expected_members = {k:v for k,v in baseline['member_score_distribution'].items() if v}
        expected_candidates = {k:v for k,v in baseline['candidate_score_distribution'].items() if v}
        assert dict(member_hist) == expected_members, 'member_distribution_mismatch'
        assert dict(candidate_hist) == expected_candidates, 'candidate_distribution_mismatch'
        assert {k:v for k,v in rejections.items() if k!='accept'} == baseline['rejection_distribution']
        assert accepted_count == baseline['accepted_relation_count']
        assert member_count == baseline['verified_member_pair_count']
        assert member_top.rows()[0]['score'] == baseline['actual_highest_member_score']
        atomic_json(OUT/'top100_selection.json',candidate_top.rows())
        atomic_json(OUT/'top100_all_members_selection.json',member_top.rows())
        atomic_json(OUT/'replay_complete.json',dict(status='PASS',candidate_count=len(candidates.pairs),
            member_count=member_count,candidate_identity_sha256=digest.hexdigest(),
            member_histogram=dict(member_hist),candidate_histogram=dict(candidate_hist),
            rejections=dict(rejections),accepted_count=accepted_count,gate_passed_members=gate_members,
            decisions=dict(decision_counts),network_reasons=dict(network_reasons),
            peak_rss_mib=peak_memory_mb(),elapsed_seconds=time.perf_counter()-started,
            old_top20_exact_score_matches=len(samples),original_aggregate_replay_matches=True))
    after = protected_hashes()
    assert before == after, 'protected_input_or_algorithm_modified'
    atomic_json(OUT/'protected_verification.json',dict(status='PASS',files=len(before),unchanged=True))
    log('replay_complete',elapsed_seconds=time.perf_counter()-started)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase',choices=['replay','expand'],required=True)
    args = parser.parse_args()
    if args.phase == 'replay':
        replay()
    else:
        from cptc_top100_report import expand
        expand()


if __name__ == '__main__':
    main()

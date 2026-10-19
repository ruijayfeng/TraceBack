"""Internal reverse dependencies and exact endpoint scheduling, no new policy."""

from collections import defaultdict
from dataclasses import asdict
import heapq
import json

from app.correlation.candidates import CandidateEvidence, CandidatePair
from app.utils.stable_id import canonical_json


def json_value(value):
    return json.loads(json.dumps(value,ensure_ascii=False,allow_nan=False))


def evidence_order(e):
    return (e.channel, e.member_ids, e.entity_id or '', e.gap_seconds,
        e.retrieval_window_seconds, e.effective_window_seconds, e.override or (),
        e.nomination_rep, e.neighbor_rep, e.hot, e.admission_limit,
        e.neighbor_rank, e.relation_facts)


def encode_endpoint(state):
    return {'proposals': {n: [list(rank), [asdict(e) for e in evidence]]
        for n, (rank, evidence) in state['proposals'].items()},
        'discoveries': {n: [asdict(e) for e in sorted(es, key=evidence_order)]
            for n, es in state['discoveries'].items()},
        'lookup_boundaries':state.get('lookup_boundaries',[])}


def decode_evidence(row):
    row = dict(row)
    for key in ('member_ids', 'relation_facts'):
        row[key] = tuple(row[key])
    if row['override'] is not None:
        row['override'] = tuple(row['override'])
    return CandidateEvidence(**row)


def decode_endpoint(row):
    return {'proposals': {n: (tuple(rank), [decode_evidence(e) for e in es])
        for n, (rank, es) in row['proposals'].items()},
        'discoveries': {n: set(decode_evidence(e) for e in es)
            for n, es in row['discoveries'].items()},
        'lookup_boundaries':row.get('lookup_boundaries',[])}


def schedule(endpoints, generator):
    """Full both-endpoint union, all discoveries, and global cutoff verbatim.

    The cached inputs came from the official generator before endpoint Top-K.
    Rarity rank maintenance needs no repeated temporal/entity neighbor lookup.
    """
    all_pairs, discoveries = {}, defaultdict(set)
    for rep, state in sorted(endpoints.items()):
        proposals = {}
        for neighbor, (_, es) in state['proposals'].items():
            rank = min(generator.rank(e.channel, e.entity_id, e.gap_seconds, neighbor) for e in es)
            proposals[neighbor] = (rank, es)
        state['proposals'] = proposals
        for neighbor, es in state['discoveries'].items():
            discoveries[tuple(sorted((rep, neighbor)))].update(es)
        for neighbor, (rank, es) in heapq.nsmallest(generator.c.max_neighbors_per_alert,
                proposals.items(), key=lambda row: row[1][0]):
            pair = tuple(sorted((rep, neighbor)))
            priority = (*rank[:3], pair)
            prior, existing = all_pairs.get(pair, (priority, []))
            all_pairs[pair] = (min(prior, priority), existing + es)
    selected = heapq.nsmallest(generator.c.max_candidate_pairs,
        all_pairs.items(), key=lambda row: row[1][0])
    pairs = {}
    for pair, (priority, es) in sorted(selected):
        unique = tuple(sorted(set(es) | discoveries[pair], key=evidence_order))
        pairs[pair] = CandidatePair(*pair, tuple(sorted({e.channel for e in unique})), unique, priority)
    priorities = {canonical_json(list(pair)): json_value(priority) for pair, (priority, _) in all_pairs.items()}
    cutoff = max((p.priority for p in pairs.values()), default=None)
    return pairs, priorities, cutoff, len(all_pairs)-len(pairs)


def duplicate_keys(scorer, aid):
    """The exact buckets used by DuplicateScorer.candidates, not heuristic keys."""
    a, meta = scorer.alerts[aid], scorer.metadata[aid]
    if a.source_record_id is not None:
        yield canonical_json(['source', a.source_namespace, a.source_record_id, a.raw_fingerprint]), None
    if meta['origin']:
        yield canonical_json(json_value(['origin', meta['origin']])), None
    if meta['payload'] is not None and meta['rule'] is not None:
        for target in sorted(meta['targets']):
            yield canonical_json(json_value(['approximate', meta['payload'], target, meta['rule']])), scorer.parameters.window_seconds
    if scorer.observation:
        for key in scorer.observation.bucket_keys(aid):
            yield canonical_json(json_value(['observation', key])), scorer.parameters.observation.window_seconds


def closure(seeds, adjacency):
    found, pending = set(seeds), list(seeds)
    while pending:
        for other in adjacency.get(pending.pop(), ()):
            if other not in found:
                found.add(other)
                pending.append(other)
    return found


def adjacency(pairs):
    result = defaultdict(set)
    for a, b in pairs:
        result[a].add(b)
        result[b].add(a)
    return result

"""Consume sealed Stage Relation and Evidence Trace artifacts, with no replay."""
import json
from pathlib import Path

from app.evidence_trace import EvidenceTrace
from app.evidence_trace.snapshot import file_sha256, load_trace_snapshot
from app.stage_relations.models import StageRelation
from .graph import StageGraphSnapshot


def safe_snapshot_path(root, path):
    root, path = Path(root).resolve(), Path(path).resolve()
    if ({p.casefold() for p in path.parts} & {'evaluation', 'ground_truth', 'historical_gt', 'archive'} or
            path.stem.casefold() in {'ground_truth', 'labels', 'gold_chain', 'attacks'}):
        raise ValueError('stage_chain_truth_path_forbidden')
    if not any(path.is_relative_to(root/folder) for folder in ('outputs', 'data/processed')):
        raise ValueError('stage_chain_source_outside_snapshot_roots')
    return path


def load_stage_graph(root, relation_manifest, evidence_manifest):
    root = Path(root).resolve()
    relation_manifest = safe_snapshot_path(root, relation_manifest)
    evidence_manifest = safe_snapshot_path(root, evidence_manifest)
    index, receipt = load_trace_snapshot(root, relation_manifest)
    evidence_hash = file_sha256(evidence_manifest)
    evidence = json.loads(evidence_manifest.read_text(encoding='utf-8-sig'))
    if evidence.get('status') != 'sealed' or evidence.get('contract_version') != 'evidence-trace-v1':
        raise ValueError('requires_sealed_existing_evidence_trace')
    directory = evidence_manifest.parent/'validated'
    verified = {}
    for name, digest in evidence['validated_output_sha256'].items():
        path = safe_snapshot_path(root, directory/name)
        if path.parent != directory or file_sha256(path) != digest:
            raise ValueError('existing_evidence_trace_hash_mismatch:' + name)
        verified[str(path)] = digest
    required = {'stage_traces.jsonl', 'relation_traces.jsonl', 'source_receipt.json'}
    if not required <= set(evidence['validated_output_sha256']):
        raise ValueError('existing_evidence_trace_files_missing')
    prior_receipt = json.loads((directory/'source_receipt.json').read_text(encoding='utf8'))
    if any(prior_receipt.get(path) != digest for path, digest in receipt.items()):
        raise ValueError('evidence_trace_source_snapshot_mismatch')
    traces = []
    for name in ('stage_traces.jsonl', 'relation_traces.jsonl'):
        traces.extend(EvidenceTrace.model_validate_json(line) for line in (directory/name).read_text(encoding='utf8').splitlines())
    manifest = json.loads(relation_manifest.read_text(encoding='utf8'))
    relation_ref, = [ref for ref in manifest['artifacts'] if ref.endswith('/stage_relations.jsonl')]
    relation_path = safe_snapshot_path(root, root/relation_ref)
    relations = [StageRelation.model_validate_json(line) for line in relation_path.read_text(encoding='utf8').splitlines()]
    snapshot = StageGraphSnapshot([t.stage for t in traces if t.subject_type == 'STAGE'], relations, traces, index)
    receipt.update(verified)
    receipt[str(evidence_manifest)] = evidence_hash
    assert_source_unchanged(receipt)
    return snapshot, receipt


def assert_source_unchanged(receipt):
    for path, expected in receipt.items():
        if file_sha256(path) != expected:
            raise ValueError('stage_chain_source_changed:' + path)

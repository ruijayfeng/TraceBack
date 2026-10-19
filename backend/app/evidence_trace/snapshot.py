"""Load immutable Stage/Relation artifacts with verified content hashes."""
import gzip
import hashlib
import json
from pathlib import Path

from app.models import CanonicalAlert
from app.stage_relations.models import StageRelation
from app.stages.models import BehaviorAnnotation, Stage
from .models import ChainReference
from .trace import EvidenceTraceIndex


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_trace_snapshot(root, manifest_path, *, chains_path=None):
    """chains_path must project an existing chain into ChainReference[].

    Its ID and membership are supplied, never inferred from connected Stages.
    A missing chain artifact leaves the index usable for Stage/Relation queries.
    """
    root, manifest_path = Path(root).resolve(), Path(manifest_path).resolve()
    def allowed(path):
        forbidden = {'evaluation', 'ground_truth', 'historical_gt', 'archive'}
        if {p.casefold() for p in path.parts} & forbidden or path.stem.casefold() in {'ground_truth', 'labels', 'attacks', 'gold_chain'}:
            raise ValueError('trace_truth_path_forbidden')
        if not any(path.is_relative_to(root / folder) for folder in ('data/processed', 'outputs')):
            raise ValueError('trace_artifact_outside_snapshot_roots')
    allowed(manifest_path)
    initial_manifest_hash = file_sha256(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding='utf8'))
    if manifest.get('status') != 'sealed' or manifest.get('algorithm_version') != 'stage-relations-v1':
        raise ValueError('trace_requires_sealed_stage_relation_snapshot')
    refs = dict(manifest['source_artifacts'])
    if set(refs) & set(manifest['artifacts']):
        raise ValueError('ambiguous_snapshot_artifact')
    refs.update(manifest['artifacts'])
    paths = {}
    for ref, digest in sorted(refs.items()):
        path = (root / ref).resolve()
        allowed(path)
        if file_sha256(path) != digest:
            raise ValueError('trace_artifact_hash_mismatch:' + ref)
        paths[ref] = path

    def read(name, model, source):
        found = [p for p in source if p.endswith('/' + name)]
        if len(found) != 1:
            raise ValueError('trace_artifact_missing_or_ambiguous:' + name)
        path = paths[found[0]]
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rt', encoding='utf8') as stream:
            return [model.model_validate_json(line) for line in stream]

    chains = []
    chain_hash = None
    if chains_path is not None:
        chains_path = Path(chains_path).resolve()
        allowed(chains_path)
        chain_hash = file_sha256(chains_path)
        chains = [ChainReference.model_validate(row) for row in json.loads(chains_path.read_text(encoding='utf8'))]
    index = EvidenceTraceIndex(manifest['analysis_id'],
        read('stage_source_alerts.jsonl.gz', CanonicalAlert, manifest['source_artifacts']),
        read('stages.jsonl.gz', Stage, manifest['source_artifacts']),
        read('behaviors.jsonl.gz', BehaviorAnnotation, manifest['source_artifacts']),
        read('stage_relations.jsonl', StageRelation, manifest['artifacts']), chains)
    receipt = {str(manifest_path): initial_manifest_hash, **{str(paths[p]): digest for p, digest in refs.items()}}
    if chains_path is not None:
        receipt[str(chains_path)] = chain_hash
    if any(file_sha256(path) != digest for path, digest in receipt.items()):
        raise ValueError('trace_input_changed_during_load')
    return index, receipt

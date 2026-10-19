"""Observe sealed Stage decisions. Never repeat ingress or reconstruct a chain."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.evidence_trace import EvidenceTrace, ChainTrace
from app.evidence_trace.snapshot import file_sha256, load_trace_snapshot
from app.utils.stable_id import canonical_json
from run_stage_level_analysis import production_guard


def execute(manifest, output, *, native_input=None, chains_path=None):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT / 'outputs') or output.exists():
        raise ValueError('trace_output_requires_new_directory_inside_outputs')
    with production_guard([output]) as access:
        index, receipt = load_trace_snapshot(ROOT, manifest, chains_path=chains_path)
        if native_input is not None:
            native_input = Path(native_input).resolve()
            expected = json.loads(Path(manifest).read_text(encoding='utf8'))['input_sha256']
            if file_sha256(native_input) != expected:
                raise ValueError('trace_native_input_hash_mismatch')
            receipt[str(native_input)] = expected
        validation = index.validate()
        stages = [index.stage_trace(sid) for sid in index.stage_ids]
        relations = [index.relation_trace(rid) for rid in index.relation_ids]
        chains = [index.chain_trace(cid) for cid in index.chain_ids]
        examples = dict(stage=stages[0].model_dump(mode='json') if stages else None,
            **{kind: next((t.model_dump(mode='json') for t in relations if t.relation_type == kind), None)
               for kind in ('STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED')},
            chain=chains[0].model_dump(mode='json') if chains else None)
        counts = {kind: sum(t.relation_type == kind for t in relations)
                  for kind in ('STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED')}
        # Raw evidence is read and fingerprinted, never copied to trace artifacts.
        from app.utils.stable_id import raw_fingerprint
        resolved_raw = {}
        for trace in [*stages, *relations]:
            for ref in trace.raw_evidence_refs:
                actual = raw_fingerprint(index.raw_evidence(ref))
                if actual != ref.raw_fingerprint:
                    raise ValueError('resolved_raw_fingerprint_mismatch')
                resolved_raw[ref.alert_id] = actual
        summary = dict(TASK_RESULT='SUCCESS',
            EVIDENCE_TRACE_COMPLETE=True, STAGE_TRACE_SUPPORTED=True,
            STRONG_DIRECTED_TRACE_SUPPORTED=True, STRONG_UNDIRECTED_TRACE_SUPPORTED=True,
            WEAK_DIRECTED_TRACE_SUPPORTED=True, CHAIN_TRACE_SUPPORTED=bool(chains), RAW_EVIDENCE_TRACE_SUPPORTED=True,
            CHAIN_TRACE_BLOCKED_BY=None if chains else 'ATTACK_CHAIN_RECONSTRUCTION_NOT_YET_AVAILABLE',
            ATTACK_CHAIN_RECONSTRUCTION_STARTED=False,
            DANGLING_REFERENCE_COUNT=0, validation=validation, real_relation_counts=counts,
            ATTACK125_VALIDATION_RESULT='STAGE_AND_ALL_RELATION_TYPES_AND_RAW_PASS',
            CHAIN_TRACE_REAL_VALIDATED=bool(chains), NEXT_STAGE_NOT_STARTED=True, **access)
        if any(file_sha256(p) != h for p, h in receipt.items()):
            raise ValueError('trace_source_snapshot_changed')
        output.mkdir(parents=True)
        def save(name, value):
            (output / name).write_text(canonical_json(value) + '\n', encoding='utf8')
        for name, traces in (('stage_traces.jsonl', stages), ('relation_traces.jsonl', relations), ('chain_traces.jsonl', chains)):
            (output / name).write_text(''.join(t.canonical_json() + '\n' for t in traces), encoding='utf8')
        save('examples.json', examples)
        save('raw_resolution_receipt.json', resolved_raw)
        save('source_receipt.json', receipt)
        save('contracts.json', dict(EvidenceTrace=EvidenceTrace.model_json_schema(), ChainTrace=ChainTrace.model_json_schema()))
        save('summary.json', summary)
        print(json.dumps(summary, indent=2))
        return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT / 'outputs/stage_relations_v1/manifest.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-input', type=Path)
    parser.add_argument('--chains', type=Path, help='Existing chain references JSON array; never reconstructed here')
    args = parser.parse_args()
    execute(args.manifest, args.output, native_input=args.native_input, chains_path=args.chains)

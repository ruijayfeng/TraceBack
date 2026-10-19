"""Reopen exported traces and compare against their sealed source decisions."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.evidence_trace import EvidenceTrace
from app.evidence_trace.snapshot import file_sha256, load_trace_snapshot
from app.utils.stable_id import canonical_json
from run_stage_level_analysis import production_guard


def verify(manifest, output):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT/'outputs'):
        raise ValueError('trace_verification_output_outside_outputs')
    with production_guard([output]) as access:
        index, _ = load_trace_snapshot(ROOT, manifest)
        receipt = json.loads((output/'source_receipt.json').read_text(encoding='utf8'))
        for path, digest in receipt.items():
            if file_sha256(path) != digest:
                raise ValueError('trace_source_receipt_changed')
        reloaded = {}
        for name, identities, getter in (('stage_traces.jsonl', index.stage_ids, index.stage_trace),
                                        ('relation_traces.jsonl', index.relation_ids, index.relation_trace)):
            rows = [EvidenceTrace.model_validate_json(line) for line in (output/name).read_text(encoding='utf8').splitlines()]
            if [t.subject_id for t in rows] != list(identities):
                raise ValueError('exported_trace_coverage_mismatch')
            for trace in rows:
                if trace != getter(trace.subject_id):
                    raise ValueError('exported_trace_differs_from_existing_decision')
                for ref in trace.raw_evidence_refs:
                    index.raw_evidence(ref)
                for pointer in trace.evidence_pointers:
                    index.resolve_evidence(pointer)
            reloaded[name] = len(rows)
        # Current scope has no reconstructed chain. Reject accidental chain output.
        if (output/'chain_traces.jsonl').read_text(encoding='utf8'):
            raise ValueError('unexpected_chain_artifact_in_current_scope')
        examples = json.loads((output/'examples.json').read_text(encoding='utf8'))
        for value in examples.values():
            if value is not None:
                trace = EvidenceTrace.model_validate(value)
                expected = index.stage_trace(trace.subject_id) if trace.subject_type == 'STAGE' else index.relation_trace(trace.subject_id)
                if trace != expected:
                    raise ValueError('example_differs_from_existing_decision')
        raw_receipt = json.loads((output/'raw_resolution_receipt.json').read_text(encoding='utf8'))
        refs = {r.alert_id:r for sid in index.stage_ids for r in index.stage_trace(sid).raw_evidence_refs}
        if raw_receipt != {aid:r.raw_fingerprint for aid,r in refs.items()}:
            raise ValueError('raw_resolution_coverage_mismatch')
        result = dict(RELOADED_TRACES=reloaded, RAW_ALERTS_VERIFIED=len(refs),
            EXACT_EXISTING_DECISIONS_PRESERVED=True, DANGLING_REFERENCE_COUNT=0,
            CHAIN_TRACE_REAL_VALIDATED=False, ATTACK_CHAIN_RECONSTRUCTION_STARTED=False, **access)
        (output/'verification.json').write_text(canonical_json(result)+'\n', encoding='utf8')
        print(json.dumps(result, indent=2))
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT/'outputs/stage_relations_v1/manifest.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    verify(args.manifest, args.output)

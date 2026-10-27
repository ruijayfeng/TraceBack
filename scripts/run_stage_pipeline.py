"""Official ① → ⑨ CLI; reconstruct chains from the completed formal ⑧ handoff."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'backend'))
from app.stage_chains.pipeline import load_attack_chain_pipeline


def execute(input_path, *, output=None, progress=None):
    if output is not None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=False)
    result = load_attack_chain_pipeline(input_path, **({'progress': progress} if progress else {}))
    if output is not None:
        upstream = result.upstream
        source = dict(alerts=[a.model_dump(mode='json') for a in upstream.community.alerts],
            entities=[e.model_dump(mode='json') for e in upstream.community.entities],
            communities=upstream.community.result.model_dump(mode='json'),
            stages=upstream.stages.model_dump(mode='json'),
            candidates=upstream.candidate_result.model_dump(mode='json'),
            evidence=upstream.evidence_result.model_dump(mode='json'),
            identity_projection=upstream.normalized.identity_projection.model_dump(mode='json'),
            statistics=upstream.statistics)
        for name, value in [('stage8.json', source), ('stage9.json', result.reconstruction.model_dump(mode='json'))]:
            (output/name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')
        receipt = dict(entry='scripts/run_stage_pipeline.py', input=str(Path(input_path).resolve()),
            input_sha256=sha256(Path(input_path).read_bytes()).hexdigest(),
            stage8_sha256=sha256((output/'stage8.json').read_bytes()).hexdigest(),
            stage9_sha256=sha256((output/'stage9.json').read_bytes()).hexdigest(),
            graph_input_digest=result.graph.input_digest,
            stage_table='stage8.json#stages.stages', relation_table='stage8.json#evidence.decisions',
            relation_id_field='candidate_id', statistics=result.statistics)
        (output/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')
    print(json.dumps(result.statistics, ensure_ascii=False, indent=2))
    return result


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='New output directory; existing paths are never overwritten')
    parser.add_argument('--progress-jsonl', action='store_true', help='Emit read-only stage notifications to stdout')
    args = parser.parse_args()
    observer = (lambda event: print('@@TRACEBACK_PROGRESS ' + json.dumps(event, ensure_ascii=False), flush=True)) if args.progress_jsonl else None
    execute(args.input, output=args.output, progress=observer)

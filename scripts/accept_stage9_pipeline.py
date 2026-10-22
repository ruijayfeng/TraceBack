"""Observe one real execution of the official CLI, with truth/snapshot read guards.

Run twice into new directories. Independent evaluation happens only after these
processes have exited and their stage8/stage9 artifacts have been sealed.
"""
import argparse
from collections import Counter
from contextlib import redirect_stdout
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
sys.dont_write_bytecode = True


def execute(input_path, output):
    output = output.resolve()
    if not output.is_relative_to(ROOT/'outputs') or output.exists():
        raise ValueError('acceptance_requires_new_outputs_directory')
    calls, order, reads, writes, denied = Counter(), [], set(), set(), []
    phase = 'setup'
    def guard(event, args):
        if phase != 'production':
            return
        if event in {'socket.connect', 'subprocess.Popen'}:
            denied.append(event)
            raise AssertionError('production_external_execution_forbidden')
        if event != 'open' or isinstance(args[0], int):
            return
        path = Path(os.fsdecode(args[0])).resolve()
        writing = args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        blocked = (writing and not path.is_relative_to(output)) or (
            not writing and not path.is_relative_to(output) and
            {'outputs', 'evaluation', 'ground_truth'} & {s.casefold() for s in path.parts})
        if blocked:
            denied.append(str(path))
            raise AssertionError('production_truth_snapshot_or_external_write:' + str(path))
        (writes if writing else reads).add(str(path))
    names = {'execute', 'load_attack_chain_pipeline', 'load_stage_pipeline', 'load_alert_pipeline',
        'ingest_records', 'extract_entities', 'filter_alerts', 'normalize_behaviors', 'build_communities',
        'aggregate_stages', 'generate_stage_pair_candidates', 'validate_stage_pair_candidates',
        'from_stage8', 'reconstruct_attack_chains', 'validate_reconstruction'}
    def profile(frame, event, arg):
        if event != 'call':
            return
        module, name = frame.f_globals.get('__name__', ''), frame.f_code.co_name
        if module.startswith(('evaluation', 'app.correlation.', 'app.stage_relations.analysis',
                              'app.chains.', 'app.stage_chains.assembly')):
            denied.append(module+'.'+name)
            raise AssertionError('nonofficial_inference_executed:' + module+'.'+name)
        if name in names and (module.startswith('app.') or module == 'official_stage_cli'):
            key = module+'.'+name
            calls[key] += 1
            order.append(key)
            if name == 'extract_entities':
                assert frame.f_locals.get('contract') == 'front-data-v1'
    spec = importlib.util.spec_from_file_location('official_stage_cli', ROOT/'scripts/run_stage_pipeline.py')
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    sys.addaudithook(guard)
    # The CLI creates the directory, so its fresh-directory guard is exercised.
    log = output.parent/(output.name+'.log')
    error = None
    with log.open('w', encoding='utf8') as stream, redirect_stdout(stream):
        phase = 'production'
        sys.setprofile(profile)
        try:
            cli.execute(input_path, output=output)
        except Exception:
            error = traceback.format_exc()
        finally:
            sys.setprofile(None)
            phase = 'audit'
    if not output.exists():
        output.mkdir()
    artifacts = {p.name: sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()}
    execution = dict(official_entry='scripts/run_stage_pipeline.py:execute', calls=dict(calls),
        call_order=order, production_reads=sorted(reads), production_writes=sorted(writes),
        denied_events=denied, ground_truth_read_during_production=False,
        artifacts_before_evaluation=artifacts, error=error,
        evaluation_modules_loaded=[n for n in sys.modules if n.split('.')[0] == 'evaluation'])
    (output/'execution.json').write_text(json.dumps(execution, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    print(json.dumps(dict(run=output.name, success=error is None, calls=dict(calls)), ensure_ascii=False))
    if error:
        raise RuntimeError(error)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    execute(args.input, args.output)

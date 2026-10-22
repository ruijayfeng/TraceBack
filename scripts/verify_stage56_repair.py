"""Verify the official ①–⑥ pipeline; protected files are hash-only sidecars."""
import argparse
from collections import Counter
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import builtins

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from verify_community_optimization import protected_hashes
from app.services.stage_pipeline import load_stage_pipeline
from app.stages import aggregate_stages, load_stage_config
from app.community import load_community_config


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def execute(input_path, output, baseline=None):
    output = Path(output).resolve()
    forbidden = [ROOT/'data', ROOT/'evaluation', ROOT/'outputs/analyses',
                 Path('D:/Code_WorkSpace/TraceBack-Dataset')]
    if any(output.is_relative_to(p.resolve()) for p in forbidden):
        raise ValueError('verification_output_cannot_be_protected')
    output.mkdir(parents=True, exist_ok=False)
    before = json.loads(Path(baseline).read_text(encoding='utf8')) if baseline else protected_hashes()
    calls, events, reads = Counter(), [], set()
    active = False
    original_import = builtins.__import__
    excluded = ('evaluation', 'app.stage_relations', 'app.stage_chains', 'app.chains',
                'app.evidence_trace', 'app.api')

    def guarded_import(name, *args, **kwargs):
        if name.startswith(excluded):
            raise RuntimeError('later_stage_import_forbidden:'+name)
        return original_import(name, *args, **kwargs)

    def guard(event, args):
        if not active:
            return
        if event == 'socket.connect':
            raise RuntimeError('network_not_part_of_stage56_verification')
        if event == 'open' and not isinstance(args[0], int):
            path = Path(os.fsdecode(args[0])).resolve()
            if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                raise RuntimeError('pipeline_write_forbidden:'+str(path))
            if any(p.casefold() in {'ground_truth', 'evaluation', 'protected', 'validated'} for p in path.parts):
                raise RuntimeError('truth_or_protected_runtime_read_forbidden:'+str(path))
            if path.suffix not in {'.py', '.pyc', '.pyd', '.dll'}:
                reads.add(str(path))

    def trace(frame, event, arg):
        if event != 'call':
            return
        name = frame.f_code.co_name
        if name in {'convert_record', 'extract_entities', 'filter_alerts', 'normalize_behaviors',
                    'build_communities', 'aggregate_stages'}:
            calls[frame.f_globals.get('__name__', '')+'.'+name] += 1
        if name in {'extract_entities', 'filter_alerts', 'normalize_behaviors', 'build_communities', 'aggregate_stages'}:
            events.append(name)

    sys.addaudithook(guard)
    active = True
    builtins.__import__ = guarded_import
    try:
        sys.setprofile(trace)
        run = load_stage_pipeline(input_path)
        sys.setprofile(None)
        assert events == ['extract_entities', 'filter_alerts', 'normalize_behaviors',
                          'build_communities', 'aggregate_stages'], 'official_pipeline_order_or_repeat'
        repeated = aggregate_stages(replace(run.community, alerts=list(reversed(run.community.alerts)),
            entities=list(reversed(run.community.entities))), run.normalized.source_settings,
            load_community_config(ROOT/'configs/community-v1.yaml'),
            load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
        assert repeated == run.stages, 'stage_repeat_instability'
        statistics = run.statistics
    finally:
        sys.setprofile(None)
        builtins.__import__ = original_import
        active = False
    print('Official pipeline completed; hashing protected files...', flush=True)
    after = protected_hashes()
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    integrity = dict(PROTECTED_FILE_COUNT=len(before), PROTECTED_DATA_SHA256_UNCHANGED=not changed,
        CHANGED_PROTECTED_FILES=changed, PROTECTED_INVENTORY_SHA256_BEFORE=digest(before),
        PROTECTED_INVENTORY_SHA256_AFTER=digest(after))
    if changed:
        raise ValueError('protected_data_changed_STOP')
    receipt = dict(calls=dict(calls), numbered_order=events, runtime_reads=sorted(reads),
                   DETERMINISTIC_REVERSE_REPLAY=True, GROUND_TRUTH_LEAKAGE=False,
                   PIPELINE_RUNTIME_WRITES=False, AI_ENABLED=False, NEXT_STAGE_STARTED=False)
    for filename, data in [('summary.json', statistics), ('integrity.json', integrity),
            ('runtime_receipt.json', receipt), ('community_result.json', run.community.result.model_dump(mode='json')),
            ('stage_result.json', run.stages.model_dump(mode='json'))]:
        (output/filename).write_text(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')
    print(json.dumps(dict(**statistics, **integrity, GROUND_TRUTH_LEAKAGE=False), ensure_ascii=False, indent=2))
    return run


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    execute(args.input, args.output, args.baseline)

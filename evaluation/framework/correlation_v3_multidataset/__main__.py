"""python -m evaluation.framework.correlation_v3_multidataset [--preflight-only]."""

import argparse
import ctypes
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'backend'))

from .common import capture_integrity, discover, freeze_recipe, read_json, truth_tripwire, write
from .pipeline import progress, run_scene, scan_scene


def windows_memory(pid=None):
    if sys.platform != 'win32':
        return None
    class Status(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
            *[(name, ctypes.c_ulonglong) for name in ('total_physical', 'available_physical',
                'total_pagefile', 'available_pagefile', 'total_virtual', 'available_virtual', 'extended_virtual')]]
    status = Status()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return {name: getattr(status, name)/(1024**2) for name in ('total_physical', 'available_physical', 'available_pagefile')}


def worker(root, scene, destination):
    """An ordinary isolated OS process, not a delegated agent.

    The resource guard aborts only when the host's available COMMIT memory falls
    below 512 MiB. It never trims inputs/candidates or silently adjusts config.
    The entire scenario is blocked with null unknown algorithm counts instead.
    """
    command = [sys.executable, '-m', 'evaluation.framework.correlation_v3_multidataset',
               '--worker', scene, '--destination', str(destination)]
    with (destination/scene/'worker.log').open('w', encoding='utf-8') as log:
        child = subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        while child.poll() is None:
            time.sleep(5)
            memory = windows_memory()
            if memory and memory['available_pagefile'] < 512:
                # The Windows venv launcher can own a second Python process.
                # Terminate only this launched worker tree, never an unrelated
                # process or a global process-name match.
                subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                child.wait()
                checkpoint = read_json(destination/scene/'pipeline_checkpoint.json')
                checkpoint.update(status='blocked', blocked_stage=checkpoint['active_stage'],
                    blocked_reason='host_available_commit_below_512_MiB', resource_state=memory,
                    limitation='worker terminated to prevent host exhaustion; no partial result is complete')
                write(destination/scene/'result.json', checkpoint)
                progress(scene, 'blocked', reason=checkpoint['blocked_reason'])
                return
        path = destination/scene/'result.json'
        if not path.exists():
            checkpoint_path = destination/scene/'pipeline_checkpoint.json'
            checkpoint = read_json(checkpoint_path) if checkpoint_path.exists() else {'dataset': scene}
            checkpoint.update(status='blocked', blocked_stage=checkpoint.get('active_stage'),
                blocked_reason='worker_exited_without_result', worker_exit_code=child.returncode)
            write(path, checkpoint)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', default=str(ROOT/'outputs/correlation_v3_multidataset'))
    parser.add_argument('--worker')
    parser.add_argument('--scan-worker', help='isolated, production-only full Adapter scan')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--resume', action='store_true', help='reuse only byte-verified Task C ingress/results, never a historical algorithm version')
    parser.add_argument('--report-only', action='store_true')
    parser.add_argument('--reproduce-observation-gap', help='read-only minimal real-input observation pointer reproduction')
    args = parser.parse_args()
    destination = Path(args.destination).resolve()
    if not destination.is_relative_to((ROOT/'outputs/correlation_v3_multidataset').resolve()):
        raise ValueError('evaluation_output_scope')
    destination.mkdir(parents=True, exist_ok=True)
    if args.worker:
        return 0 if run_scene(ROOT, args.worker, destination/args.worker)['status'] == 'completed' else 2
    datasets, config, settings, recipe = freeze_recipe(ROOT)
    if args.reproduce_observation_gap:
        from .diagnosis import reproduce_observation_pointer_gap
        path = Path(args.reproduce_observation_gap).resolve()
        if not path.is_relative_to(destination):
            raise ValueError('reproduction_input_scope')
        sample = read_json(path)
        if sample.get('config_hash') != recipe['config_hash']:
            raise ValueError('reproduction_config_mismatch')
        with truth_tripwire(ROOT):
            result = [reproduce_observation_pointer_gap(s, config, settings, recipe['config_hash']) for s in sample['samples']]
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.scan_worker:
        with truth_tripwire(ROOT):
            return 0 if scan_scene(ROOT, datasets[args.scan_worker], config, destination/args.scan_worker)['status'] == 'ready' else 2
    if not args.report_only:
        baseline_path = destination/'protected_before.json'
        if baseline_path.exists() and not args.resume:
            raise ValueError('existing_task_c_artifacts_require_explicit_resume')
        if not baseline_path.exists():
            progress('all', 'capture_protected_hashes')
            write(baseline_path, capture_integrity(ROOT))
        if (destination/'recipe.json').exists():
            if read_json(destination/'recipe.json') != recipe:
                raise ValueError('frozen_recipe_changed_do_not_resume')
        else:
            write(destination/'recipe.json', recipe)
        inventory = discover(ROOT, datasets)
        write(destination/'dataset_inventory.json', inventory)
        # Finish ALL production-only data validation before labels are opened.
        for row in inventory:
            scene = row['dataset']
            if row['status'] != 'files_present_unvalidated':
                continue
            directory = destination/scene
            existing = directory/'preflight.json'
            if args.resume and existing.exists():
                from app.services.storage import file_digest
                ingress = read_json(existing)
                if any(file_digest(ROOT/i['path']) != i['sha256'] for i in ingress['inputs']):
                    raise ValueError('resume_raw_input_changed')
                if file_digest(directory/'canonical_ingress.jsonl.gz') != ingress['canonical_ingress_sha256']:
                    raise ValueError('resume_ingress_changed')
                continue
            with truth_tripwire(ROOT):
                scan_scene(ROOT, datasets[scene], config, directory)
        if args.preflight_only:
            return 0
        selected = sorted((s for s in datasets if (destination/s/'preflight.json').exists()),
                          key=lambda s: (read_json(destination/s/'preflight.json')['canonical_alert_count'], s))
        for scene in selected:
            ingress = read_json(destination/scene/'preflight.json')
            if ingress['status'] != 'ready':
                write(destination/scene/'result.json', {'dataset': scene, 'status': 'blocked',
                    'blocked_stage': 'adapter', 'blocked_reason': 'full_adapter_data_readiness_failed',
                    'counts': {'raw_alert_count': ingress['raw_alert_count'], 'canonical_alert_count': ingress['canonical_alert_count']},
                    'field_coverage': ingress['field_coverage']})
                continue
            if args.resume and (destination/scene/'result.json').exists():
                old = read_json(destination/scene/'result.json')
                if old.get('config_hash') != recipe['config_hash']:
                    raise ValueError('resume_result_config_mismatch')
                continue
            progress(scene, 'start_full_isolated_pipeline')
            worker(ROOT, scene, destination)
    # Only now may the offline evaluator load labels. No labels enter any
    # production function argument, config, adapter, triage, or candidate.
    from .report import generate_report
    result = generate_report(ROOT, destination)
    progress('all', 'report_complete', TASK_C_RESULT=result)
    return 0 if result != 'C_EVALUATION_BLOCKED' else 2


if __name__ == '__main__':
    raise SystemExit(main())

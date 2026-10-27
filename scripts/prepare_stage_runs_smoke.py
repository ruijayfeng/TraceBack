"""Prepare small existing test inputs and an explicitly failed UI test run.

Never reads/re-runs protected datasets. The injected failure only exercises
orchestration diagnostics and cannot produce a successful analysis result.
"""
import argparse
import json
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'backend/tests'))
from test_stage9_pipeline import native
from app.services.stage_runs import StageRunService


def prepare(seed_failure=False):
    output = ROOT / 'outputs/workbench_productization_checks'
    output.mkdir(parents=True, exist_ok=True)
    input_path = native(output)
    if seed_failure:
        service = StageRunService(ROOT)
        try:
            upload_id = secrets.token_hex(32)
            directory = service.upload_directory(upload_id)
            directory.mkdir(parents=True, exist_ok=False)
            (directory / 'alerts.jsonl').write_bytes(input_path.read_bytes())
            service.register_upload(upload_id, 'smoke-intentional-failure.jsonl')
            service.command = lambda record: [sys.executable, '-u', '-c',
                "import sys; print('intentional CLI failure for UI diagnostics',file=sys.stderr); sys.exit(7)"]
            record = service.create(upload_id)
            deadline = time.monotonic()+15
            while time.monotonic() < deadline:
                record = service.status(record['run_id'])
                if record['status'] == 'FAILED':
                    break
                time.sleep(.1)
            if record['status'] != 'FAILED':
                raise RuntimeError('expected diagnostic failure did not complete')
            (output / 'ui-failure-run.json').write_text(json.dumps(record,indent=2),encoding='utf8')
            print('Diagnostic FAILED run:',record['run_id'])
        finally:
            service.close()
    print('Existing native test fixture:',input_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed-failure',action='store_true')
    prepare(parser.parse_args().seed_failure)

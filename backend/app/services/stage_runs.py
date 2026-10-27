"""Durable upload/run orchestration around the official CLI, without algorithms.

One worker per application serializes subprocesses. Atomic JSON records survive
restarts; interrupted owners are failed explicitly, never replayed or published.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

from pydantic import ValidationError

from app.services.alert_pipeline import ROOT, native_alert_adapters
from app.services.pipeline_progress import STAGES
from app.services.queries import QueryError
from app.services.storage import atomic_json, checked_id
from app.stage_chains.stage9_reader import Stage9ArtifactReader

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
ACTIVE = {'QUEUED', 'VALIDATING', 'RUNNING'}
ENTRY = 'scripts/run_stage_pipeline.py'


def error_field(record, adapter):
    """Locate adapter failures by replaying its pure normalizers for diagnosis.

    These probes do not accept/reject records; convert_record is authoritative.
    """
    from app.adapters.multisource import PATHS
    from app.entities import normalization as norm
    if not isinstance(record.get('event'), dict):
        return 'event'
    raw = record['event']
    if adapter.native_source != 'ids' and raw.get('source_type') != adapter.native_source:
        return 'event.source_type'
    try:
        adapter.parse_time(raw.get('timestamp'))
    except (ValueError, TypeError, OverflowError):
        return 'event.timestamp'
    if 'timestamp' in record:
        try:
            if adapter.parse_time(record['timestamp']) != adapter.parse_time(raw.get('timestamp')):
                return 'timestamp'
        except (ValueError, TypeError, OverflowError):
            return 'timestamp'
    for name, key in PATHS.get(adapter.native_source, {}).items():
        if key not in raw:
            continue
        fn = norm.ip if name.endswith('_ip') else norm.integer if name.endswith('_port') else norm.hostname if name in {'host','domain'} else norm.url if name == 'url' else norm.text
        try:
            fn(raw[key])
        except (ValueError, TypeError, OverflowError):
            return 'event.'+key
    for key in ('process_id','parent_process_id','pid','ppid','worker_process_id'):
        if key in raw and raw[key] not in (None,''):
            try:
                norm.integer(raw[key])
            except (ValueError, TypeError, OverflowError):
                return 'event.'+key
    return '$'


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def validate_input(path):
    """Validate every physical JSONL line through the CLI's own native adapters.

    No repairs/default semantic values are supplied. IDs are generated only by
    the existing adapter's canonical identity rule, exactly as in the CLI.
    """
    adapters = native_alert_adapters()
    errors, count, invalid, seen = [], 0, 0, set()
    with Path(path).open('rb') as stream:
        for line_number, raw in enumerate(stream, 1):
            count += 1
            record, adapter = None, None
            try:
                line = raw.decode('utf-8-sig' if line_number == 1 else 'utf-8')
                if not line.strip():
                    raise ValueError('empty_record')
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError('record_must_be_object')
                source = record.get('source_type')
                if not isinstance(source, str) or source not in adapters:
                    errors.append(dict(line=line_number, field='source_type', reason='unsupported_or_missing_source_type'))
                    invalid += 1
                    continue
                adapter = adapters[source]
                alert = adapter.convert_record(record)
                if alert.alert_id in seen:
                    raise ValueError('duplicate_canonical_alert_id')
                seen.add(alert.alert_id)
            except ValidationError as exc:
                invalid += 1
                for error in exc.errors(include_input=False, include_context=False, include_url=False):
                    errors.append(dict(line=line_number, field='.'.join(map(str, error['loc'])) or '$', reason=error['msg']))
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
                invalid += 1
                reason = str(exc)[:400] or type(exc).__name__
                field = error_field(record, adapter) if adapter else '$'
                errors.append(dict(line=line_number, field=field, reason=reason))
    if not count:
        errors.append(dict(line=0, field='$', reason='empty_dataset'))
    return dict(status='VALID' if count and not errors else 'INVALID', total_count=count,
                valid_count=count-invalid, invalid_count=invalid, errors=errors)


class StageRunService:
    def __init__(self, root, *, timeout_seconds=900):
        self.root = Path(root).resolve()
        self.base = self.root / 'outputs/workbench_runs'
        self.timeout_seconds = timeout_seconds
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='stage-run')

    def directory(self, run_id):
        try:
            return self.base / 'runs' / checked_id(run_id)
        except ValueError:
            raise QueryError(404, 'stage_run_not_found') from None

    def read(self, run_id):
        try:
            with self.lock:
                record = json.loads((self.directory(run_id) / 'run.json').read_text(encoding='utf8'))
        except FileNotFoundError:
            raise QueryError(404, 'stage_run_not_found') from None
        if record['run_id'] != run_id:
            raise QueryError(409, 'stage_run_identity_mismatch')
        return record

    def save(self, record):
        with self.lock:
            record['updated_at'] = now()
            atomic_json(self.directory(record['run_id']) / 'run.json', record)

    def recover(self):
        from app.services.analysis import owner_alive
        for path in (self.base / 'runs').glob('ana_*/run.json'):
            record = self.read(path.parent.name)
            if record['status'] in ACTIVE and not owner_alive(record.get('owner_pid')):
                self.fail(record, 'application_interrupted; input and logs retained')

    def close(self):
        self.executor.shutdown(wait=True)

    def upload_directory(self, upload_id):
        if not isinstance(upload_id, str) or len(upload_id) != 64 or any(c not in '0123456789abcdef' for c in upload_id):
            raise QueryError(404, 'stage_upload_not_found')
        return self.base / 'uploads' / upload_id

    def register_upload(self, upload_id, filename):
        directory = self.upload_directory(upload_id)
        path = directory / 'alerts.jsonl'
        validation = validate_input(path)
        record = dict(upload_id=upload_id, filename=filename, size_bytes=path.stat().st_size,
                      sha256=digest(path), created_at=now(), validation=validation)
        atomic_json(directory / 'upload.json', record)
        return record

    def create(self, upload_id):
        directory = self.upload_directory(upload_id)
        try:
            upload = json.loads((directory / 'upload.json').read_text(encoding='utf8'))
        except FileNotFoundError:
            raise QueryError(404, 'stage_upload_not_found') from None
        if upload['validation']['status'] != 'VALID':
            raise QueryError(422, 'stage_input_validation_failed')
        source = directory / 'alerts.jsonl'
        if digest(source) != upload['sha256']:
            raise QueryError(409, 'stage_input_hash_mismatch')
        run_id = 'ana_' + secrets.token_hex(32)
        target = self.directory(run_id)
        (target / 'input').mkdir(parents=True, exist_ok=False)
        input_path = target / 'input/alerts.jsonl'
        input_path.write_bytes(source.read_bytes())
        if digest(input_path) != upload['sha256']:
            raise QueryError(409, 'stage_input_hash_mismatch')
        version_files = [ROOT / ENTRY, *sorted((ROOT / 'configs').rglob('*.yaml'))]
        record = dict(run_id=run_id, analysis_id=run_id, filename=upload['filename'],
            input_sha256=upload['sha256'], size_bytes=upload['size_bytes'], input_count=upload['validation']['total_count'],
            validation=upload['validation'], status='QUEUED', created_at=now(), started_at=None,
            finished_at=None, duration_seconds=None, pipeline=ENTRY,
            pipeline_version={str(p.relative_to(ROOT)): digest(p) for p in version_files},
            input_path=str(input_path), output_path=str(target / 'result'), log_path=str(target / 'run.log'),
            owner_pid=os.getpid(), child_pid=None, exit_code=None, current_stage=None, failed_stage=None,
            stages=[dict(stage=i+1, name=name, status='PENDING') for i, name in enumerate(STAGES)],
            failure_reason=None, result_available=False, artifact_type='attack-chain-reconstruction-v1',
            artifacts={}, counts=None)
        with self.lock:
            self.save(record)
            try:
                self.executor.submit(self.execute, run_id)
            except Exception as exc:
                self.fail(record, f'queue_submission_failed: {exc}')
        return record

    def fail(self, record, reason):
        record.update(status='FAILED', failure_reason=reason, finished_at=now(), result_available=False,
                      failed_stage=record['current_stage'])
        if record['started_at']:
            record['duration_seconds'] = (datetime.fromisoformat(record['finished_at']) - datetime.fromisoformat(record['started_at'])).total_seconds()
        for stage in record['stages']:
            if stage['status'] == 'RUNNING':
                stage['status'] = 'FAILED'
        self.save(record)

    def command(self, record):
        return [sys.executable, '-u', str(ROOT / ENTRY), '--input', record['input_path'],
                '--output', record['output_path'], '--progress-jsonl']

    def progress(self, record, line):
        if not line.startswith('@@TRACEBACK_PROGRESS '):
            return
        event = json.loads(line.split(' ', 1)[1])
        number = event['stage']
        if not isinstance(number, int) or not 1 <= number <= 9 or event['name'] != STAGES[number-1] or event['status'] not in {'RUNNING', 'COMPLETED'}:
            raise ValueError('invalid_cli_progress_event')
        record['stages'][number-1].update(status=event['status'], updated_at=now())
        record['current_stage'] = event['name']
        self.save(record)

    def execute(self, run_id):
        record = self.read(run_id)
        process = None
        try:
            record.update(status='VALIDATING', started_at=now(), current_stage='输入校验')
            self.save(record)
            if digest(record['input_path']) != record['input_sha256']:
                raise ValueError('stage_input_hash_mismatch')
            record['validation'] = validate_input(record['input_path'])
            if record['validation']['status'] != 'VALID':
                raise ValueError('stage_input_validation_failed')
            record.update(status='RUNNING', current_stage='启动正式 CLI', command=self.command(record))
            self.save(record)
            started = time.monotonic()
            with open(record['log_path'], 'wb') as log, open(record['log_path'], encoding='utf8', errors='replace') as tail:
                process = subprocess.Popen(record['command'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, shell=False)
                record['child_pid'] = process.pid
                self.save(record)
                while True:
                    done = process.poll() is not None
                    for line in tail:
                        self.progress(record, line)
                    if done:
                        record['exit_code'] = process.returncode
                        self.save(record)
                        break
                    if time.monotonic() - started > self.timeout_seconds:
                        process.kill()
                        process.wait()
                        record['exit_code'] = process.returncode
                        raise TimeoutError(f'formal_cli_timeout_after_{self.timeout_seconds}_seconds')
                    time.sleep(.15)
            if record['exit_code'] != 0:
                raise RuntimeError(f'formal_cli_failed_with_exit_code_{record["exit_code"]}; see run.log')
            record['current_stage'] = '产物完整性检查'
            self.save(record)
            _, counts = self.check_artifacts(record)
            record.update(artifacts={p.name: digest(p) for p in Path(record['output_path']).iterdir() if p.is_file()}, counts=counts)
            atomic_json(self.directory(run_id) / 'result_binding.json', dict(run_id=run_id,
                input_sha256=record['input_sha256'], artifacts=record['artifacts']))
            record.update(status='SUCCEEDED', result_available=True, finished_at=now(), current_stage='完成')
            record['duration_seconds'] = (datetime.fromisoformat(record['finished_at']) - datetime.fromisoformat(record['started_at'])).total_seconds()
            self.save(record)
        except Exception as exc:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
                record['exit_code'] = process.returncode
            with open(record['log_path'], 'a', encoding='utf8') as log:
                log.write(f'\nORCHESTRATION ERROR: {type(exc).__name__}: {exc}\n')
            self.fail(record, f'{type(exc).__name__}: {exc}')

    def check_artifacts(self, record):
        directory = self.directory(record['run_id'])
        if Path(record['input_path']) != directory / 'input/alerts.jsonl' or Path(record['output_path']) != directory / 'result':
            raise ValueError('run_path_binding_mismatch')
        output = Path(record['output_path'])
        receipt = json.loads((output / 'receipt.json').read_text(encoding='utf8'))
        if receipt['entry'] != ENTRY or Path(receipt['input']) != Path(record['input_path']) or receipt['input_sha256'] != record['input_sha256'] or digest(record['input_path']) != record['input_sha256']:
            raise ValueError('receipt_input_binding_mismatch')
        for name in ('stage8', 'stage9'):
            if digest(output / (name+'.json')) != receipt[name+'_sha256']:
                raise ValueError('artifact_hash_mismatch')
        if receipt['statistics']['INPUT_ALERTS'] != record['input_count']:
            raise ValueError('receipt_input_count_mismatch')
        reader = Stage9ArtifactReader(self.root, output)
        data = reader.load()
        if data['input_digest'] != receipt['graph_input_digest'] or data['graph_input_digest'] != data['input_digest']:
            raise ValueError('graph_digest_mismatch')
        # Validate complete partitions without invoking the reconstruction algorithm.
        chains = data['reconstruction'].chains
        stage_ids = [sid for chain in chains for sid in chain.stage_ids]
        relation_ids = [rid for chain in chains for rid in chain.relation_ids]
        if sorted(stage_ids) != sorted(data['stages']) or sorted(relation_ids) != sorted(data['relations']):
            raise ValueError('incomplete_chain_partition')
        return reader, reader.overview()['counts']

    def verify_registered(self, record):
        """Recheck registered bytes without parsing every historical graph on polls."""
        run_id = record['run_id']
        if record['status'] != 'SUCCEEDED' or not record['result_available']:
            raise QueryError(409, 'stage_run_result_unavailable')
        try:
            binding = json.loads((self.directory(run_id) / 'result_binding.json').read_text(encoding='utf8'))
            if binding != dict(run_id=run_id, input_sha256=record['input_sha256'], artifacts=record['artifacts']):
                raise ValueError('run_result_binding_mismatch')
            directory = self.directory(run_id)
            if Path(record['input_path']) != directory / 'input/alerts.jsonl' or Path(record['output_path']) != directory / 'result':
                raise ValueError('run_path_binding_mismatch')
            if digest(record['input_path']) != record['input_sha256'] or set(record['artifacts']) != {'stage8.json', 'stage9.json', 'receipt.json'}:
                raise ValueError('run_registered_input_or_artifacts_mismatch')
            for name, expected in record['artifacts'].items():
                if name not in {'stage8.json', 'stage9.json', 'receipt.json'} or digest(Path(record['output_path']) / name) != expected:
                    raise ValueError('run_result_hash_mismatch')
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise QueryError(409, 'stage_run_artifacts_invalid') from exc

    def reader(self, run_id):
        record = self.read(run_id)
        self.verify_registered(record)
        try:
            return self.check_artifacts(record)[0]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise QueryError(409, 'stage_run_artifacts_invalid') from exc

    def status(self, run_id):
        record = self.read(run_id)
        if record['result_available']:
            try:
                self.verify_registered(record)
            except QueryError as exc:
                record = dict(record, result_available=False, unavailable_reason=exc.code)
        path = self.directory(run_id) / 'run.log'
        if path.is_file():
            with path.open('rb') as log:
                log.seek(max(0, path.stat().st_size-32768))
                record['recent_log'] = log.read().decode('utf8', errors='replace')
        else:
            record['recent_log'] = ''
        return record

    def history(self):
        records = [self.status(p.parent.name) for p in (self.base / 'runs').glob('ana_*/run.json')]
        return sorted(records, key=lambda r: r['created_at'], reverse=True)

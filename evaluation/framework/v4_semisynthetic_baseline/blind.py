"""Fresh worker: native schemas -> unchanged production v4 -> sealed outputs.

No GT reader or evaluation matching code is imported into this worker.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import gzip
import json
import os
from pathlib import Path
import sys
import time

from .common import OUT, ROOT, THRESHOLD, VERSION, read, save, sha
from evaluation.framework.v5_truth_guard import reject_truth_fields
from app.adapters.base import AdapterSettings
from app.adapters.suricata import SuricataAdapter
from app.adapters.wazuh import WazuhAdapter
from app.adapters.cptc import strict_json
from app.chains.assembly import run_reconstruction
from app.correlation.candidates import candidate_diagnosis
from app.correlation.edges import run_correlation
from app.correlation.index import AlertIndex
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.services.storage import restore_config


@contextmanager
def replay_guard(input_path, destination):
    """Audit tripwire for trusted Python; no claim of an OS/native-code sandbox."""
    allowed = Path(input_path).resolve()
    output = Path(destination).resolve()
    roots = (ROOT.resolve(), Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve())
    active, events, reads = [True], [], set()
    def audit(event, args):
        if not active[0]:
            return
        if event in {'subprocess.Popen', 'os.system', 'os.spawn', 'os.posix_spawn'}:
            events.append({'event': event, 'rejected': True})
            raise PermissionError('child process forbidden in blind worker')
        if event != 'open':
            return
        name, mode, flags = args
        if isinstance(name, int):
            raise PermissionError('preopened file descriptors are not replay inputs')
        p = Path(os.fsdecode(name)).resolve()
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        generated = p.is_relative_to(output)
        importing = p.suffix in {'.py', '.pyc', '.pyd', '.dll'} and any(p.is_relative_to(r) for r in roots)
        permitted = generated if writing else p == allowed or generated or importing
        if not permitted:
            events.append({'event': event, 'path': str(p), 'rejected': True})
            raise PermissionError('non-allowlisted blind file: ' + str(p))
        if not writing and not importing:
            reads.add(str(p))
    sys.addaudithook(audit)
    try:
        yield events, reads
    finally:
        active[0] = False


def namespace(raw):
    if raw.get('event_type') == 'alert':
        return 'suricata'
    if isinstance(raw.get('rule'), dict) and isinstance(raw.get('agent'), dict):
        groups = raw['rule'].get('groups', [])
        return 'wazuh.authentication' if any('authentication' in g for g in groups) else 'wazuh.host'
    raise ValueError('unsupported_native_alert_shape')


def write_models(name, values, destination):
    with gzip.open(destination / (name + '.jsonl.gz'), 'wt', encoding='utf8') as handle:
        for obj in values:
            handle.write(obj.canonical_json() + '\n')


def run():
    if (OUT / 'blind_run_manifest.json').exists() or (OUT / 'evaluation_started.json').exists():
        raise RuntimeError('replay_is_single_use_and_precedes_truth')
    prepared = read(OUT / 'preparation.json')
    config = restore_config(prepared['algorithm'])
    settings = {k: AdapterSettings(**v) for k, v in prepared['sources'].items()}
    adapters = {k: (SuricataAdapter if k == 'suricata' else WazuhAdapter)(config, v)
                for k, v in settings.items()}
    destination = OUT / 'blind'
    if destination.exists():
        raise RuntimeError('blind_working_directory_exists; inspect interrupted run before restarting')
    destination.mkdir()
    started = time.perf_counter()
    stages, source_counts, by_id, line_map = {}, Counter(), {}, []
    # Import optional lazily used modules before enabling the read allowlist.
    import ctypes.wintypes  # noqa: F401
    with replay_guard(prepared['input'], destination) as (events, reads):
        tick = time.perf_counter()
        with Path(prepared['input']).open(encoding='utf8') as handle:
            for line_no, line in enumerate(handle, 1):
                raw = strict_json(line)
                reject_truth_fields(raw)
                ns = namespace(raw)
                alert = adapters[ns].convert(raw)
                source_counts[ns] += 1
                if alert.alert_id in by_id and by_id[alert.alert_id].canonical_json() != alert.canonical_json():
                    raise ValueError('conflicting_canonical_identity')
                by_id[alert.alert_id] = alert
                # Opaque ordinal is evaluation locator, never a domain identity/feature.
                line_map.append({'final_line': line_no, 'alert_id': alert.alert_id})
        if len(line_map) != 10051:
            raise ValueError('input_count_not_10051')
        stages['ingest_seconds'] = time.perf_counter() - tick
        print(json.dumps({'stage': 'ingest', 'rows': len(line_map), 'unique_alerts': len(by_id),
                          'sources': source_counts}), flush=True)
        alerts = [by_id[k] for k in sorted(by_id)]
        tick = time.perf_counter()
        dedupe = deduplicate(alerts, config, settings)
        if not dedupe.is_complete:
            raise ValueError('dedupe_incomplete')
        stages['dedupe_seconds'] = time.perf_counter() - tick
        tick = time.perf_counter()
        extracted = extract_entities(alerts, settings)
        alerts, entities = extracted.alerts, extracted.entities
        stages['extraction_seconds'] = time.perf_counter() - tick
        save(destination / 'input_line_map.json', line_map)
        for name, values in [('canonical', alerts), ('dedupe', dedupe.groups), ('entities', entities)]:
            write_models(name, values, destination)
        def progress(value):
            print(json.dumps(value, ensure_ascii=False), flush=True)
        with gzip.open(destination / 'diagnostics.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as handle:
            def sink(row):
                handle.write(json.dumps(row, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n')
            def candidate_summary(value):
                save(destination / 'candidate_diagnosis.json', value)
            with candidate_diagnosis(candidate_summary):
                correlation = run_correlation(alerts, dedupe.groups, entities, config, settings,
                                              diagnostic_sink=sink, progress=progress)
            if not correlation.record.is_complete:
                raise ValueError('correlation_incomplete:' + str(correlation.record.incomplete_reason))
            reconstruction = run_reconstruction(alerts, dedupe.groups, entities, correlation.edges,
                config, settings, upstream_record=correlation.record, diagnostic_sink=sink, progress=progress)
        if not reconstruction.record.is_complete:
            raise ValueError('reconstruction_incomplete')
        for name, values in [('correlation_edges', correlation.edges), ('incidents', reconstruction.incidents),
                             ('chains', reconstruction.chains)]:
            write_models(name, values, destination)
        index = AlertIndex(alerts, dedupe.groups, entities)
        save(destination / 'frequency_snapshot.json', index.frequency_snapshot())
        save(destination / 'owner.json', index.owner)
        save(destination / 'correlation_record.json', correlation.record.model_dump(mode='json'))
        save(destination / 'reconstruction_record.json', reconstruction.record.model_dump(mode='json'))
        save(destination / 'correlation_summary.json', correlation.summary)
        save(destination / 'reconstruction_summary.json', reconstruction.summary)
        save(destination / 'dedupe_diagnostics.json', dedupe.diagnostics)
        save(destination / 'guard_receipt.json', {'rejected_events': events,
            'non_code_reads': sorted(reads), 'only_external_data_file': prepared['input'],
            'ground_truth_loaded': False, 'guard_type': 'trusted Python audit tripwire'})
    sealed = {p.relative_to(OUT).as_posix(): sha(p) for p in sorted(destination.rglob('*')) if p.is_file()}
    save(OUT / 'blind_run_manifest.json', {'status': 'completed', 'is_complete': True,
        'algorithm_version': VERSION, 'threshold': THRESHOLD, 'config_hash': correlation.record.config_hash,
        'algorithm_config_hash': config.config_hash, 'mapping_digest': config.mapping_digest,
        'input_sha256': prepared['input_sha256'], 'ground_truth_loaded': False,
        'raw_alert_count': len(line_map), 'canonical_count': len(alerts),
        'source_counts': dict(source_counts), 'stages': stages,
        'total_seconds': time.perf_counter() - started, 'files': sealed})
    print(json.dumps({'stage': 'blind_completed', 'correlation_edges': len(correlation.edges),
        'chain_edges': reconstruction.summary['chain_edge_count']}), flush=True)


if __name__ == '__main__':
    run()

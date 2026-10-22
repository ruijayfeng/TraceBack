"""Label-free native ingress -> sealed Community/IncidentCandidate artifacts.

No evaluation imports or truth paths are accepted. Wrapper IDs go only to an
external trace map; the builder receives CanonicalAlert facts exclusively.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))

from app.adapters.base import AdapterSettings
from app.adapters.multisource import MultiSourceAdapter
from app.community import load_community_config, prepare_communities
from app.community.evidence import PROJECTION_VERSION, profile
from app.config import load_config, read_yaml
from app.noise_filter import load_noise_config
from app.stages.config import load_stage_config
from app.utils.stable_id import canonical_json, content_digest, id_for


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value)+'\n', encoding='utf8')


def write_models(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Zero mtime and empty filename make repeated exports byte-stable as well.
    with path.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
            for row in rows:
                data = row.model_dump(mode='json') if hasattr(row,'model_dump') else row
                zipped.write((canonical_json(data)+'\n').encode('utf8'))


def peak_memory_mb():
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount',wintypes.DWORD),
                *[(name,ctypes.c_size_t) for name in ('PeakWorkingSetSize','WorkingSetSize',
                    'QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage',
                    'QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        function = ctypes.windll.psapi.GetProcessMemoryInfo
        function.argtypes = [wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
        if function(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):
            return counters.PeakWorkingSetSize/1048576
        return None
    import resource
    scale = 1048576 if sys.platform == 'darwin' else 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/scale


def execute(input_path, output, profiles_path, algorithm_path, policy_path, *, noise_policy_path=None):
    input_path, output = Path(input_path).resolve(), Path(output).resolve()
    if any(part.lower() in {'evaluation','ground_truth','hard_negative','attack'} for part in input_path.parts):
        raise ValueError('input_must_be_unannotated_security_alerts')
    before = sha(input_path)
    config = load_config(algorithm_path,deployment_override=ROOT/'configs/front-data-sources.yaml')
    policy = load_community_config(policy_path)
    noise_policy = load_noise_config(noise_policy_path) if noise_policy_path else load_noise_config()
    behavior_policy = load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    source_profiles = read_yaml(profiles_path)['sources']
    adapters = {s:MultiSourceAdapter(config,AdapterSettings(**v),s) for s,v in source_profiles.items()}
    snapshot = dict(projection_version=PROJECTION_VERSION, normalization=config.snapshot,community=policy.model_dump(mode='json'),
                    noise_filter=noise_policy.model_dump(mode='json'),
                    behavior_stage=behavior_policy.model_dump(mode='json'),
                    sources={a.settings.source_namespace:a.settings.snapshot() for a in adapters.values()})
    source_hashes = {p.relative_to(ROOT).as_posix():sha(p) for folder in ('backend/app','configs')
                     for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
    # Preserve an implementation receipt before the first label-free prediction.
    save(output/'implementation_receipt.json', dict(files=source_hashes,config_snapshot=snapshot))
    trace, counts = [], Counter()
    started = time.perf_counter()
    def canonical_alerts():
        with input_path.open(encoding='utf8') as f:
            for line in f:
                record = json.loads(line)
                source = record['source_type']
                alert = adapters[source].convert_record(record)
                trace.append(dict(event_id=record.get('event_id'),alert_id=alert.alert_id,source=source))
                counts[source] += 1
                yield alert
    run = prepare_communities(canonical_alerts(),{a.settings.source_namespace:a.settings for a in adapters.values()},policy,
                              noise_config=noise_policy, behavior_config=behavior_policy)
    runtime = time.perf_counter()-started
    if sha(input_path) != before:
        raise ValueError('native_input_changed_during_prediction')
    result = run.result
    effective_hash = content_digest(snapshot)
    analysis_id = id_for('AnalysisRecord',dict(input_alert_ids=sorted({a.alert_id for a in run.noise_filter.original_alerts}),
        config_hash=effective_hash,algorithm_version=policy.version+'+'+PROJECTION_VERSION,schema_version='1.0'))
    domain = ROOT/'data/processed'/analysis_id
    detail = ROOT/'outputs/analyses'/analysis_id
    write_models(domain/'noise_source_alerts.jsonl.gz',run.noise_filter.original_alerts)
    write_models(domain/'noise_audit.jsonl.gz',run.noise_filter.audit_records)
    write_models(domain/'alert_behaviors.jsonl.gz',run.behaviors)
    save(detail/'noise_summary.json',run.noise_filter.statistics)
    write_models(domain/'community_alerts.jsonl.gz',sorted(run.alerts,key=lambda a:a.alert_id))
    write_models(domain/'community_entities.jsonl.gz',sorted(run.entities,key=lambda e:e.entity_id))
    write_models(domain/'incident_candidates.jsonl.gz',result.incident_candidates)
    # Export the exact typed postings and their witnesses, including incomplete
    # flows and recall-only contexts. These are projections, not new facts/edges.
    entity_map = {e.entity_id:e for e in run.entities}
    typed_counts = defaultdict(set)
    def projections():
        for alert in sorted(run.alerts, key=lambda a:a.alert_id):
            settings = next(a.settings for a in adapters.values() if a.settings.source_namespace == alert.source_namespace)
            projected = profile(alert, entity_map, settings, policy)
            for b in projected.bindings:
                family = ('session' if b.kind in ('session', 'connection', 'application_session') else b.kind)
                if b.projection == 'binding' and family in ('request','flow','session','task'):
                    typed_counts[family].add(b.key)
                from app.models.base import resolve_pointer
                normalized = json.loads(b.identity)
                if b.projection == 'entity':
                    entity = entity_map[b.entity_ids[0]]
                    normalized = dict(type=entity.type.value,scope=entity.scope,value=entity.value)
                yield dict(alert_id=alert.alert_id,source=alert.source_namespace,source_type=alert.source_type.value,
                    type=b.kind,projection=b.projection,identity_key=b.key,normalized_value=normalized,
                    complete=b.complete,missing_fields=list(b.missing_fields),entity_ids=list(b.entity_ids),
                    witnesses=[dict(source_field=pointer,original_value=resolve_pointer(alert.raw_alert,pointer)) for pointer in b.pointers])
    write_models(domain/'entity_binding_context_index.jsonl.gz',projections())
    save(detail/'frequency_snapshot.json',dict(host_counts=dict(sorted(Counter(
        o.entity_id for a in run.alerts for o in a.entity_occurrences if o.role.value == 'host').items()))))
    detail.mkdir(parents=True,exist_ok=True)
    with (detail/'diagnostics.jsonl').open('w',encoding='utf8') as f:
        for row in result.diagnostics:
            f.write(canonical_json(row)+'\n')
    save(output/'trace_map.json',sorted(trace,key=lambda r:(r['alert_id'],r['event_id'] or '')))
    observable = defaultdict(Counter)
    for alert in run.alerts:
        source = next(k for k,a in adapters.items() if a.settings.source_namespace == alert.source_namespace)
        observable[source]['alerts'] += 1
        for kind in {c.kind for c in alert.contexts}:
            observable[source][kind] += 1
        for kind,paths in policy.projections.get(adapters[source].settings.format_profile,{}).items():
            from app.models.base import resolve_pointer
            for pointer in paths:
                try:
                    value=resolve_pointer(alert.raw_alert,pointer)
                except ValueError:
                    continue
                if value is not None and value != '':
                    observable[source][kind] += 1
                    break
        if alert.process:
            observable[source]['process_identity'] += int(bool(alert.host and (alert.process.guid or alert.process.instance_id or
                alert.process.pid is not None and alert.process.start_time)))
    entity_counts = Counter(e.type.value for e in run.entities)
    summary = dict(result.statistics, CANONICAL_ALERTS=len(run.noise_filter.original_alerts), REJECTED_ALERTS=0,
                   **{k+'_ENTITIES':entity_counts[k] for k in ('HOST','ACCOUNT','PROCESS')},
                   **{k.upper()+'_BINDINGS':len(typed_counts[k]) for k in ('request','flow','session','task')},
                   binding_count_unit='distinct_typed_identity_keys_complete_only',
                   COMMUNITY_SIZES=sorted(c.member_count for c in result.incident_candidates),
                   TASK_RESULT='ENTITY_BINDING_INDEX_REPAIRED_COMMUNITY_REBUILT',
                   CURRENT_PIPELINE_STAGE='COMMUNITY_BUILDER_COMPLETE',NEXT_STAGE_NOT_STARTED=True,
                   by_source=dict(sorted(counts.items())), runtime_seconds=runtime,
                   peak_process_working_set_mb=peak_memory_mb(),observability={s:dict(c) for s,c in sorted(observable.items())})
    artifacts = {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(domain.iterdir())}
    artifacts.update({p.relative_to(ROOT).as_posix():sha(p) for p in sorted(detail.iterdir()) if p.name != 'manifest.json'})
    manifest = dict(analysis_id=analysis_id,contract_version=policy.version,projection_version=PROJECTION_VERSION,status='sealed',input=str(input_path),
        input_sha256=before,input_fingerprint=result.input_fingerprint,config_hash=effective_hash,
        community_policy_hash=result.config_hash,config_snapshot=snapshot,mapping_digest=config.mapping_digest,
        summary=summary,artifacts=artifacts,
        trace_map_sha256=sha(output/'trace_map.json'),implementation_receipt_sha256=sha(output/'implementation_receipt.json'),
        scope='CanonicalAlert -> core evidence -> index -> tier matcher -> join/merge/create -> IncidentCandidate')
    save(detail/'manifest.json',manifest)
    save(output/'manifest.json',manifest)
    save(output/'summary.json',summary)
    print(json.dumps(dict(analysis_id=analysis_id,**summary),indent=2))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/community_v1')
    parser.add_argument('--profiles',type=Path,default=ROOT/'configs/front-data-profiles.yaml')
    parser.add_argument('--algorithm',type=Path,default=ROOT/'configs/algorithm-v5-evidence-semantics.yaml')
    parser.add_argument('--policy',type=Path,default=ROOT/'configs/community-v1.yaml')
    parser.add_argument('--noise-policy', type=Path, default=None)
    args = parser.parse_args()
    execute(args.input,args.output,args.profiles,args.algorithm,args.policy,noise_policy_path=args.noise_policy)


if __name__ == '__main__':
    main()

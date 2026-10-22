"""NOT_OFFICIAL_ANALYSIS_PIPELINE: native-input/index diagnostics only.

Run evaluation only after this process seals its domain artifacts and manifest.
"""
import argparse
from collections import Counter
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
from app.config import load_config, read_yaml
from app.correlation.candidates import candidate_diagnosis
from app.services.front_data import prepare_front_data
from app.utils.stable_id import canonical_json, content_digest, id_for
from front_data_baseline import hashes


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(canonical_json(value)+'\n',encoding='utf8')


def write_models(path, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with gzip.open(path,'wt',encoding='utf8') as f:
        for row in rows:
            f.write(row.canonical_json() if hasattr(row,'canonical_json') else canonical_json(row))
            f.write('\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--profiles',type=Path,default=ROOT/'configs/front-data-profiles.yaml')
    p.add_argument('--algorithm',type=Path,default=ROOT/'configs/algorithm-v5-evidence-semantics.yaml')
    p.add_argument('--output',type=Path,default=ROOT/'outputs/front_data_layer')
    args=p.parse_args()
    path=args.input.resolve()
    if any(part.lower() in {'evaluation','ground_truth','hard_negative','attack'} for part in path.parts):
        raise ValueError('input_must_be_unannotated_security_alerts')
    config=load_config(args.algorithm,deployment_override=ROOT/'configs/front-data-sources.yaml')
    profiles=read_yaml(args.profiles)['sources']
    adapters={s:MultiSourceAdapter(config,AdapterSettings(**v),s) for s,v in profiles.items()}
    input_hash=sha(path)
    trace=[]
    def records():
        for line in path.open(encoding='utf8'):
            record=json.loads(line)
            # Wrapper IDs are retained only in an external trace table for the evaluator.
            # They are never used by extraction, indexing or ranking.
            alert=adapters[record['source_type']].convert_record(record)
            trace.append(dict(event_id=record.get('event_id'),alert_id=alert.alert_id,source=record['source_type']))
            yield record
    started=time.perf_counter()
    reports=[]
    with candidate_diagnosis(reports.append):
        result=prepare_front_data(records(),adapters,config)
    summary=result.summary
    summary['runtime_seconds']=time.perf_counter()-started
    if sha(path)!=input_hash:
        raise ValueError('input_changed_during_validation')
    snapshot=dict(algorithm=config.snapshot,sources={a.settings.source_namespace:a.settings.snapshot() for a in adapters.values()})
    config_hash=content_digest(snapshot)
    analysis_id=id_for('AnalysisRecord',dict(input_alert_ids=list(result.index.alerts),config_hash=config_hash,
                                            algorithm_version='front-data-v1',schema_version='1.0'))
    domain=ROOT/'data/processed'/analysis_id
    detail=ROOT/'outputs/analyses'/analysis_id
    write_models(domain/'front_alerts.jsonl.gz',result.index.alerts.values())
    write_models(domain/'front_entities.jsonl.gz',result.index.entities.values())
    write_models(domain/'front_candidates.jsonl.gz',(
        dict(alert_ids=list(c.support_key),channels=list(c.channels),evidence=[e.json_data() for e in c.evidence])
        for c in result.candidates.pairs))
    save(args.output/'trace_map.json',trace)
    detail.mkdir(parents=True,exist_ok=True)
    with (detail/'diagnostics.jsonl').open('w',encoding='utf8') as f:
        for row in result.candidates.diagnostics:
            f.write(canonical_json(row)+'\n')
    save(detail/'frequency_snapshot.json',result.index.frequency_snapshot())
    save(args.output/'candidate_diagnostics.json',reports[0])
    samples=[]
    for key,ref in sorted(result.index.context_refs.items()):
        if ref.kind not in {row['type'] for row in samples}:
            samples.append(dict(type=ref.kind,key=key,value=ref.value,scope=ref.scope,alert_ids=list(result.index.context_members[key])[:5]))
    for kind in ('HOST','ACCOUNT','PROCESS','IP'):
        e=next((e for e in result.index.entities.values() if e.type.value==kind),None)
        if e:
            samples.append(dict(type=kind.lower(),key=kind.lower()+':'+e.entity_id,value=e.value,scope=e.scope,alert_ids=e.alert_ids[:5]))
    save(args.output/'index_samples.json',samples)
    before=json.loads((args.output/'before_hashes.json').read_text(encoding='utf8'))
    after=hashes()
    changed={k:dict(before=before.get(k),after=after.get(k)) for k in sorted(set(before)|set(after)) if before.get(k)!=after.get(k)}
    allowed={'backend/app/models/alerts.py','backend/app/adapters/base.py','backend/app/adapters/multisource.py',
             'backend/app/entities/extraction.py','backend/app/entities/context.py','backend/app/entities/front_data.py',
             'backend/app/correlation/index.py','backend/app/correlation/candidates.py','backend/app/services/front_data.py',
             'backend/app/services/incremental.py'}
    unexpected=[k for k in changed if k not in allowed and not k.startswith('configs/front-data-') and not k.startswith('configs/mappings/front-')]
    acceptance=dict(six_sources=all(summary['by_source'].get(s,0)>0 for s in profiles),
        full_dataset=9000<=summary['total_alerts']<=11000,
        no_input_loss=summary['input_alerts']==summary['total_alerts'],
        no_resource_truncation=not result.candidates.candidate_truncated,
        candidate_reduction=summary['candidate_count']<summary['global_alert_pair_count'],
        only_reliable_channels=set(summary['candidate_channels'])<= {'HOST','ACCOUNT','PROCESS','IP','request','flow','session','task','explicit_relation','source_complement'},
        frozen_modules_unchanged=not unexpected)
    summary['acceptance']=acceptance
    summary['status']='PASS' if all(acceptance.values()) else 'FAIL'
    manifest=dict(analysis_id=analysis_id,contract_version='front-data-v1',input=str(path),input_sha256=input_hash,
        config_hash=config_hash,config_snapshot=snapshot,mapping_digest=config.mapping_digest,
        dataset_digest=content_digest([[aid,a.raw_fingerprint] for aid,a in result.index.alerts.items()]),
        summary=summary,artifacts={str(p.relative_to(ROOT)):sha(p) for p in sorted(domain.iterdir())},
        frozen_module_changes=unexpected,files_changed=changed,
        scope='Adapter -> CanonicalAlert -> core extraction -> index -> candidates; no correlation scoring or downstream execution')
    save(detail/'manifest.json',manifest)
    save(args.output/'manifest.json',manifest)
    save(args.output/'summary.json',summary)
    print(json.dumps(summary,indent=2))
    if summary['status']!='PASS':
        raise SystemExit(1)


if __name__=='__main__':
    main()

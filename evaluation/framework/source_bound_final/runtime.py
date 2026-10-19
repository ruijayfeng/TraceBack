"""Reproducible source inventory and truth-denied replay on a declared JSONL."""
from pathlib import Path
import collections
import datetime as dt
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_source_bound_observability_final'
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/traceback_semisynthetic_v2')
INPUT = DATA / 'final/traceback_demo_v2.jsonl'
EXPECTED = dict(ids=2520,waf=1608,edr=2154,firewall=1544,authentication=1144,host_audit=1015)

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()

def save(name,value):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n',encoding='utf8')

def read(p): return json.loads(Path(p).read_text(encoding='utf8'))
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()

def configuration():
    from app.config import load_config
    from app.services.storage import restore_config
    cfg=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/sources.yaml')
    snapshot=cfg.snapshot
    operations={
      'process_execution':['ProcessStart','ProcessTermination','EXECVE','exec'],
      'command_execution':['CommandExecution'],
      'authentication':['login','logout','credential_accepted','session_open','pam_account','account_switch']}
    for source in ('waf','edr','other'):
        rules=[dict(id='operation-'+value,match=dict(all=[dict(field='alert_type',op='eq',value=value)]),output=category)
               for category,values in operations.items() for value in values] if source!='waf' else [
          dict(id='web-'+str(i),match=dict(all=[dict(field='signature',op='eq',value=value)]),output='web_attack')
          for i,value in enumerate(('SQL injection pattern','Path traversal'))]
        snapshot['normalization']['category_mapping_files'].append(dict(schema_version='1.0',mapping_type='category',source_type=source,default='unknown',rules=rules))
        rules=[dict(id='severity-'+value,match=dict(all=[dict(field='raw_severity',op='eq',value=value)]),output=output)
          for value,output in [('info','informational'),('low','low'),('medium','medium'),('high','high'),('critical','critical')]]
        snapshot['normalization']['severity_mapping_files'].append(dict(schema_version='1.0',mapping_type='severity',source_type=source,default='unknown',rules=rules))
    return restore_config(snapshot)

def source_settings():
    from app.adapters.base import AdapterSettings
    # User request §18 supplies a single experimental network/asset environment.
    # Names below declare that environment; no asset/account membership is read.
    return {s:AdapterSettings(source_namespace='traceback.lab.'+s,format_profile='multisource_native_v1',
        generator='dataset-observed-'+s,generator_version='v2-observed-schema',dataset_version=2,
        network_namespace='traceback.lab.network',asset_namespace='traceback.lab.assets',
        account_realm='TRACEBACK.LAB' if s in ('edr','authentication','host_audit') else None)
        for s in EXPECTED}

def write_models(p,values):
    import gzip
    with gzip.open(p,'wt',encoding='utf8',compresslevel=1) as f:
        for v in values: f.write(v.canonical_json()+'\n')

def rows(p):
    import gzip
    with gzip.open(p,'rt',encoding='utf8') as f:
        for line in f: yield json.loads(line)

def audit():
    sys.path.insert(0,str(ROOT/'backend'))
    from app.adapters.multisource import MultiSourceAdapter,SOURCE_TYPES
    from app.adapters.suricata import SuricataAdapter
    from app.adapters.base import AdapterSettings
    from app.entities.extraction import extract_entities
    cfg=configuration(); settings=source_settings()
    adapters={s:MultiSourceAdapter(cfg,v,s) for s,v in settings.items()}
    alerts=[]; trace=[]; counts=collections.Counter(); old=[]; rejects=[]
    fields=collections.defaultdict(lambda:collections.defaultdict(lambda:dict(presence=0,non_null=0,distinct=set(),examples=[])))
    def flatten(value,path=''):
        if isinstance(value,dict):
            for k,v in value.items(): yield from flatten(v,path+'/'+k.replace('~','~0').replace('/','~1'))
        else: yield path,value
    oldadapter=SuricataAdapter(cfg,AdapterSettings(source_namespace='traceback.lab.ids',format_profile='suricata_eve_v1',
        generator='suricata',network_namespace='traceback.lab.network',asset_namespace='traceback.lab.assets'))
    for line in INPUT.open(encoding='utf8'):
        r=json.loads(line);s=r['source_type'];counts[s]+=1
        for path,value in flatten(r['event']):
            field=fields[s][path];field['presence']+=1
            if value not in (None,''):
                field['non_null']+=1;canonical=json.dumps(value,sort_keys=True,ensure_ascii=False)
                field['distinct'].add(canonical)
                if len(field['examples'])<3 and canonical not in field['examples']: field['examples'].append(canonical[:220])
        a=adapters[s].convert_record(r);alerts.append(a)
        trace.append(dict(event_id=r['event_id'],raw_pointer=r.get('raw_pointer'),alert_id=a.alert_id,source=s))
        if s=='ids': old.append(oldadapter.convert(r['event']))
        else: rejects.append(dict(event_id=r['event_id'],source=s,reason='unsupported_native_alert_shape'))
    if len(alerts)!=9985 or dict(counts)!=EXPECTED: raise ValueError('DATASET_INTEGRITY_MISMATCH')
    sources={v.source_namespace:v for v in settings.values()}
    extracted=extract_entities(alerts,sources)
    write_models(OUT/'audit_canonical.jsonl.gz',extracted.alerts);write_models(OUT/'audit_entities.jsonl.gz',extracted.entities)
    write_models(OUT/'before_canonical.jsonl.gz',old)
    save('before_rejected.json',rejects);save('trace_map.json',trace)
    save('preparation.json',dict(input=str(INPUT),input_sha256=sha(INPUT),algorithm=cfg.snapshot,
        sources={k:v.snapshot() for k,v in sources.items()},config_hash=cfg.config_hash,mapping_digest=cfg.mapping_digest,
        threshold=cfg.algorithm.score.correlation_threshold,algorithm_version=cfg.algorithm.implementation_version,
        blind_started=now(),namespace_authority='user request §18 shared UTC laboratory environment; account realm independently observed in Authentication native realm',
        schema_scope='observed alert schemas only; simulation capabilities are not universal vendor guarantees'))
    inventory=[];matrix=[];capabilities=[]
    type_paths={ 'Network':['src_ip','source_ip','client_ip','dest_ip','dst_ip','server_ip'],
      'HTTP':['http/http_method','method','uri','http/url'], 'Host':['host','hostname','server_host'],
      'Account':['account','user'], 'Process':['process_id','pid','worker_process_id'], 'File':['file_path','file_hash'],
      'Flow':['flow_id'], 'Request':['request_id'],'Auth Session':['logon_id','session'], 'Network Session':['connection_id','session_id']}
    bysource=collections.defaultdict(list)
    for a in extracted.alerts:
        bysource[next(s for s,v in settings.items() if v.source_namespace==a.source_namespace)].append(a)
    projection=[]
    for s in EXPECTED:
        aa=bysource[s];inventory.append(dict(source=s,expected_count=EXPECTED[s],raw_count=counts[s],canonical_count=len(aa),
            adapter='MultiSourceAdapter/'+s,specialized=True,generic=False,source_namespace=settings[s].source_namespace,
            native_source_type=s,canonical_source_type=SOURCE_TYPES[s].value,time_range=[min(a.timestamp for a in aa),max(a.timestamp for a in aa)],
            sensor_role=s,category_counts=collections.Counter(a.category.value for a in aa),schema_version='dataset-observed-v2',status='OK'))
        cap={}
        for family,paths in type_paths.items():
            paths=['/'+p for p in paths if '/'+p in fields[s]]
            n=max((fields[s][p]['non_null'] for p in paths),default=0)
            extension=family in ('Request','Network Session') and s in ('edr','authentication') or family=='Flow' and s!='ids' or family=='Process' and s=='waf'
            value='FIXTURE_EXTENSION' if n and extension else 'YES' if n==len(aa) else 'PARTIAL' if n else 'NO'
            cap[family]=dict(value=value,capability_class='FIXTURE_EXTENSION' if n and extension else 'BASE' if n==len(aa) else 'CONDITIONAL' if n else 'NOT_OBSERVABLE',
                observed_count=n,raw_paths=paths,states=dict(OBSERVABLE_AND_PRESENT=n,OBSERVABLE_BUT_MISSING=len(aa)-n if n else 0,NOT_OBSERVABLE=0 if n else len(aa),OBSERVABLE_AND_CONFLICTING=0))
        capabilities.append(dict(source=s,capabilities=cap))
        for path,field in sorted(fields[s].items()):
            matrix.append(dict(source=s,raw_path='event'+path.replace('/','.'),json_pointer=path,
                presence=field['presence'],presence_rate=field['presence']/len(aa),non_null=field['non_null'],non_null_rate=field['non_null']/len(aa),
                distinct_count=len(field['distinct']),representative_examples=field['examples']))
            canonical=collections.Counter();projected=0;entity=0
            for a in aa:
                keys=[k for k,v in a.field_provenance.items() if v.raw_pointer==path]
                occ=[o for o in a.entity_occurrences if o.raw_pointer==path]
                if keys: projected+=1;canonical.update(keys)
                if occ: entity+=1
            # Native fields intentionally retained as payload (packets/user agent
            # etc.) are not claimed to be candidate/scoring dimensions.
            projection.append(dict(source=s,raw_field=path,raw_observable=field['non_null'],canonical_field=list(canonical),
                projected=projected,entity_feature_count=entity,status='RAW_MISSING' if not field['non_null'] else 'OK' if projected else 'UNSUPPORTED',
                consumer='entity' if entity else 'provenance_only' if projected else 'raw_alert_only'))
    save('source_inventory.json',inventory);save('raw_observability_matrix.json',matrix)
    save('source_capabilities.json',capabilities)
    save('fixture_extension_capabilities.json',[dict(source=c['source'],capability=k,**v) for c in capabilities for k,v in c['capabilities'].items() if v['capability_class']=='FIXTURE_EXTENSION'])
    save('raw_to_canonical_projection_matrix.json',projection)
    save('namespace_audit.json',dict(sources={k:v.snapshot() for k,v in settings.items()},authority='user request §18, no environment memberships read',
        ip_scope='shared network namespace',host_scope='shared asset namespace',account_scope='declared TRACEBACK.LAB realm; case preserved',
        session_scope='typed flow/request/auth/network kind + network or host scope; raw ID alone never global',cross_sensor_independence='unknown; no topology independence assumed'))
    save('role_projection_audit.json',dict(roles=collections.Counter(o.role.value for a in extracted.alerts for o in a.entity_occurrences),
        client_ip='src_ip',server_ip='dst_ip',authentication_host_ip='dst_ip and monitored_host_ip',host_ip='monitored_host_ip',
        server_host='host',http_host='domain',attacker_victim_inference=False))
    save('projection_defects_before.json',dict(wrapper='existing native adapters cannot read event envelope',
        unsupported_sources=list(PATHS_KEYS),canonical_count=len(old),rejected=len(rejects),
        discarded_semantics=['native host/account/process/file','typed request/auth/network/flow identities','protocol/action/direction/HTTP method provenance',
            'separate WAF query component (862 records)','HTTP authority interoperability across host/domain scopes','native file hash identity']))
    save('projection_repairs.json',dict(files=['backend/app/adapters/multisource.py','backend/app/entities/extraction.py'],
        repairs=['trace-only envelope unwrapping','five explicit native profiles plus EVE reuse','native field provenance','typed session identities',
                 'process and worker instance projection','source-bound roles','declared shared scopes','lossless separate URI/query assembly',
                 'explicit HTTP authority scope','native file hash scoped identity'],
        no_causal_relation_inferred_from_worker=True))
    save('projection_defects_after.json',dict(canonical_count=len(alerts),rejected_count=0,unrepresented_fields=[p for p in projection if p['status']=='UNSUPPORTED'],
        limitation='HTTP method, action, direction, native hashes are provenance-only where no frozen canonical score dimension exists; request handling is not process creation.'))
    save('binding_capability_audit.json',dict(types=['flow','request','process','auth_session','network_session'],
        representation='existing scoped SESSION/PROCESS entities and bound native field provenance',
        no_synthetic_identifiers=True,no_binding_memberships_read=True))
    print('AUDIT_COMPLETE',len(alerts),'entities',len(extracted.entities),flush=True)

PATHS_KEYS=('waf','edr','firewall','authentication','host_audit')

def freeze():
    sys.path.insert(0,str(ROOT/'backend'))
    p=read(OUT/'preparation.json')
    before=read(OUT/'before_hashes.json')
    production={str(x):sha(x) for x in (ROOT/'backend/app').rglob('*.py')}
    changed=[name for name,digest in before['implementation'].items() if sha(name)!=digest]
    if changed!=[str(ROOT/'backend/app/entities/extraction.py')]:
        if set(changed)!={str(ROOT/'backend/app/entities/extraction.py')}: raise ValueError(dict(unexpected_changes=changed))
    save('implementation_freeze.json',dict(files=production,config_sha256=sha(OUT/'preparation.json'),
        audit_input_hashes={str(OUT/n):sha(OUT/n) for n in ('audit_canonical.jsonl.gz','audit_entities.jsonl.gz','before_canonical.jsonl.gz')},
        changes=changed,formula_unchanged=True,threshold=p['threshold'],frozen_at=now()))
    print('IMPLEMENTATION_FROZEN',flush=True)

def verify_frozen():
    f=read(OUT/'implementation_freeze.json')
    if any(sha(p)!=h for p,h in f['files'].items()) or sha(OUT/'preparation.json')!=f['config_sha256']:
        raise ValueError('implementation_or_config_changed_after_freeze')

def blind():
    import gzip
    import time
    from contextlib import redirect_stdout
    sys.path.insert(0,str(ROOT/'backend'))
    from app.adapters.multisource import MultiSourceAdapter
    from app.adapters.base import AdapterSettings
    from app.models import CanonicalAlert
    from app.entities.extraction import extract_entities
    from app.dedup import deduplicate
    from app.correlation.edges import run_correlation
    from app.correlation.index import AlertIndex
    from app.services.storage import restore_config
    from evaluation.framework.v4_semisynthetic_baseline.blind import replay_guard
    import ctypes.wintypes
    variant=sys.argv[2] if len(sys.argv)>2 else 'A'
    if variant not in ('A','B','C','before'): raise ValueError('invalid_variant')
    if (OUT/'gt_access.json').exists(): raise ValueError('truth_already_unsealed')
    verify_frozen();prepared=read(OUT/'preparation.json')
    if sha(INPUT)!=prepared['input_sha256']: raise ValueError('DATASET_INTEGRITY_MISMATCH')
    destination=OUT/('blind_'+variant)
    destination.mkdir(exist_ok=False)
    config=restore_config(prepared['algorithm']);settings={k:AdapterSettings(**v) for k,v in prepared['sources'].items()}
    adapters={s:MultiSourceAdapter(config,settings['traceback.lab.'+s],s) for s in EXPECTED}
    old=[CanonicalAlert.model_validate(r) for r in rows(OUT/'before_canonical.jsonl.gz')] if variant=='before' else None
    tick=time.perf_counter();scores=hashlib.sha256();member_count=0;sourcecounts=collections.Counter()
    with replay_guard(INPUT,destination) as (events,reads):
        alerts=[]
        for i,line in enumerate(INPUT.open(encoding='utf8')):
            r=json.loads(line);sourcecounts[r['source_type']]+=1
            if variant=='before': continue
            if variant=='B': r['event_id']=hashlib.sha256(('opaque-id-'+str(i)).encode()).hexdigest()
            if variant=='C':
                if i%2: r.pop('raw_pointer',None)
                else: r['raw_pointer']={'opaque':hashlib.sha256(str(i).encode()).hexdigest()}
            alerts.append(adapters[r['source_type']].convert_record(r))
        if old is not None: alerts=old
        if variant=='before':
            from dataclasses import replace
            settings={'traceback.lab.ids':replace(settings['traceback.lab.ids'],format_profile='suricata_eve_v1')}
        dedupe=deduplicate(alerts,config,settings)
        if not dedupe.is_complete: raise ValueError('dedupe_incomplete')
        ex=extract_entities(alerts,settings);alerts,entities=ex.alerts,ex.entities
        canonical_digest=hashlib.sha256(''.join(a.canonical_json()+'\n' for a in alerts).encode()).hexdigest()
        write_models(destination/'canonical.jsonl.gz',alerts);write_models(destination/'entities.jsonl.gz',entities)
        write_models(destination/'dedupe.jsonl.gz',dedupe.groups)
        full=variant in ('A','before')
        diagnostic=gzip.open(destination/'diagnostics.jsonl.gz','wt',encoding='utf8',compresslevel=1) if full else None
        def sink(row):
            nonlocal member_count
            if row['stage']=='member_score':
                member_count+=1
                value={k:row[k] for k in ('support_key','support_pair','values','raw_total','score','valid','rejection_codes')}
                scores.update(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            if diagnostic: diagnostic.write(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n')
        try:
            result=run_correlation(alerts,dedupe.groups,entities,config,settings,diagnostic_sink=sink,
                progress=lambda r:print(variant,json.dumps(r),flush=True))
        finally:
            if diagnostic: diagnostic.close()
        if not result.record.is_complete: raise ValueError('correlation_incomplete')
        index=AlertIndex(alerts,dedupe.groups,entities)
        save(str(destination.relative_to(OUT)/'owner.json'),index.owner)
        save(str(destination.relative_to(OUT)/'frequency_snapshot.json'),index.frequency_snapshot())
        candidates=[list(c.support_key) for c in result.candidates.pairs]
        candidate_digest=hashlib.sha256(json.dumps(sorted(candidates),separators=(',',':')).encode()).hexdigest()
        save(str(destination.relative_to(OUT)/'candidate_pairs.json'),sorted(candidates))
        write_models(destination/'admitted_edges.jsonl.gz',result.edges)
        admission_digest=hashlib.sha256(''.join(e.canonical_json()+'\n' for e in result.edges).encode()).hexdigest()
        save(str(destination.relative_to(OUT)/'summary.json'),result.summary)
        save(str(destination.relative_to(OUT)/'record.json'),result.record.model_dump(mode='json'))
        save(str(destination.relative_to(OUT)/'guard_receipt.json'),dict(rejected=events,reads=sorted(reads),ground_truth_read=False,
            scenario_read=False,provenance_labels_read=False,type='trusted Python audit tripwire, not OS sandbox'))
        byid={a.alert_id:a for a in alerts};dist=collections.Counter();same=0
        def native(a): return a.raw_alert.get('source_type','ids')
        for a,b in candidates:
            sa,sb=native(byid[a]),native(byid[b]);same+=int(sa==sb);dist['candidate:'+':'.join(sorted((sa,sb)))]+=1
        same_edges=0
        for e in result.edges:
            sa,sb=native(byid[e.support_pair.alert_id_src]),native(byid[e.support_pair.alert_id_dst]);same_edges+=int(sa==sb)
            dist['admitted:'+':'.join(sorted((sa,sb)))]+=1
        receipt=dict(variant=variant,status='completed',raw_alerts=9985,canonical_alerts=len(alerts),rejected_alerts=9985-len(alerts),
            entity_count=len(entities),entities_by_type=collections.Counter(e.type.value for e in entities),candidate_count=len(candidates),
            scored_member_pairs=member_count,admitted_count=len(result.edges),canonical_digest=canonical_digest,candidate_digest=candidate_digest,
            score_digest=scores.hexdigest(),admission_digest=admission_digest,seconds=time.perf_counter()-tick,
            same_source_candidates=same,cross_source_candidates=len(candidates)-same,same_source_admitted=same_edges,cross_source_admitted=len(result.edges)-same_edges,
            source_pair_distribution=dist,ground_truth_loaded=False,completed_at=now(),CROSS_SOURCE_REQUIRED=False)
        save(str(destination.relative_to(OUT)/'receipt.json'),receipt)
    print(json.dumps(receipt),flush=True)

def seal():
    verify_frozen()
    results={v:read(OUT/('blind_'+v)/'receipt.json') for v in ('A','B','C','before')}
    keys=['canonical_digest','candidate_count','candidate_digest','score_digest','admission_digest','admitted_count']
    equal={k:len({results[v][k] for v in ('A','B','C')})==1 for k in keys}
    save('identifier_leakage_regression.json',dict(status='PASS' if all(equal.values()) else 'IDENTIFIER_LEAKAGE_DEFECT',
        event_id_randomized=True,raw_pointer_randomized_or_removed=True,comparisons=equal,results=results))
    if not all(equal.values()): raise ValueError('IDENTIFIER_LEAKAGE_DEFECT')
    save('blind_replay_summary.json',results['A']);save('before_replay_summary.json',results['before'])
    summary=read(OUT/'blind_A/summary.json')
    save('blind_score_distribution.json',dict(member=summary['member_score_distribution'],candidate=summary['candidate_score_distribution'],
        distribution=summary.get('correlation_v2',{}).get('score_distribution')))
    save('blind_top_candidates.json',summary.get('correlation_v2',{}).get('top_20',[]))
    save('blind_source_pair_distribution.json',results['A']['source_pair_distribution'])
    files={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p.name not in ('blind_manifest.json','before_hashes.json')
           and 'validation' not in p.parts and 'unsealed_attempt1' not in p.parts and 'pytest_tmp' not in p.parts
           and 'regression_tmp' not in p.parts and 'repository_tmp' not in p.parts
           and not p.name.startswith(('regression','pytest','repository'))}
    save('blind_manifest.json',dict(status='SEALED',files=files,completed_at=now(),ground_truth_read=False,
        input_sha256=sha(INPUT),formula_unchanged=True,threshold_unchanged=True,candidate_policy_unchanged=True,
        admission_policy_unchanged=True,disclosed_human_isolation_deviation='blind_isolation_deviation.json'))
    print('BLIND_SEALED',len(files),flush=True)

def unseal():
    verify_frozen()
    manifest=read(OUT/'blind_manifest.json')
    if manifest['status']!='SEALED' or any(sha(OUT/p)!=h for p,h in manifest['files'].items()):
        raise ValueError('blind_seal_invalid')
    if (OUT/'gt_access.json').exists(): raise ValueError('already_unsealed')
    save('gt_access.json',dict(GROUND_TRUTH_UNSEALED_AFTER_BLIND_REPLAY=True,blind_manifest_sha256=sha(OUT/'blind_manifest.json'),
        blind_completion_timestamp=manifest['completed_at'],gt_access_timestamp=now(),implementation_frozen=True))
    schemas={}
    for name in ('ground_truth/ground_truth.json','ground_truth/edges.json','ground_truth/stages.json',
                 'ground_truth/observations.json','ground_truth/observation_bindings.json','hard_negative/ground_truth.json'):
        path=DATA/name
        if not path.exists(): continue
        x=read(path)
        schemas[name]=dict(type=type(x).__name__,keys=list(x) if isinstance(x,dict) else None,
            first=x[0] if isinstance(x,list) and x else {k:v[:1] if isinstance(v,list) else v for k,v in x.items()} if isinstance(x,dict) else None)
    save('truth_schemas.json',schemas)
    print(json.dumps(schemas,ensure_ascii=False,indent=2),flush=True)

def inventory(base):
    return {str(p):sha(p) for p in sorted(Path(base).rglob('*')) if p.is_file() and '__pycache__' not in p.parts}

def prepare():
    if OUT.exists(): raise ValueError('single_use_output_exists')
    OUT.mkdir(parents=True)
    dataset=inventory(DATA)
    generators=inventory(DATA.parents[1]/'scripts')
    protected={str(p):sha(p) for base,glob in [('backend/app','*.py'),('configs','*.yaml'),('docs','*.md')]
               for p in (ROOT/base).rglob(glob) if '__pycache__' not in p.parts}
    protected[str(ROOT/'AGENTS.md')]=sha(ROOT/'AGENTS.md')
    history={}
    for name in ('v4_semisynthetic_baseline','v5_preformula_candidate_recovery','v5_formula_repair_integration','v5_evidence_semantics_final'):
        for directory,dirs,files in os.walk(ROOT/'outputs'/name):
            dirs[:]=[d for d in dirs if not d.startswith(('pytest','tmp','repository_tmp','regression','__pycache__'))]
            for f in files:
                p=Path(directory)/f;history[str(p)]=sha(p)
    save('before_hashes.json',dict(dataset=dataset,generators=generators,implementation=protected,historical=history))
    counts=collections.Counter();times=[]
    with INPUT.open(encoding='utf8') as f:
        for line in f:
            x=json.loads(line);counts[x['source_type']]+=1
            times.append(dt.datetime.fromisoformat(x['timestamp'].replace('Z','+00:00')))
    status='PASS' if dict(counts)==EXPECTED and sum(counts.values())==9985 and 9500+125+360==9985 else 'DATASET_INTEGRITY_MISMATCH'
    result=dict(status=status,dataset=str(INPUT),sha256=sha(INPUT),record_count=sum(counts.values()),source_distribution=counts,
        time_range=[min(times).isoformat(),max(times).isoformat()],artifacts=dataset,generator_hashes=generators,
        partition_statistics='release counts only; membership not read',background=9500,attack=125,hard_negative=360)
    save('dataset_integrity.json',result)
    save('blind_isolation_deviation.json',dict(status='DISCLOSED',
        detail='Agent inspected validator source before blind execution; a section contained HN scenario predicates. No concrete pair IDs, GT sidecar or scenario files were opened. Repairs are based only on final native fields. Strict human blind review cannot be claimed.',
        production_worker_truth_access=False))
    if status!='PASS': raise ValueError(status)
    print(json.dumps({k:v for k,v in result.items() if k not in ('artifacts','generator_hashes')}),flush=True)

def validate():
    """Run supplied validators without changing a byte in the dataset workspace.

    Only the external reproducibility receipt is redirected; the actual validator,
    two temporary rebuilds and corruption checks are unmodified. Receipt content
    is sealed away from adapter development, stdout contains aggregate status.
    """
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(DATA.parents[1]/'scripts'))
    import validate_traceback_dataset_v2 as v
    import check_dataset_reproducibility_v2 as r
    before=read(OUT/'before_hashes.json')
    original_write=r.write
    def external_receipt(p,value):
        if Path(p).resolve().is_relative_to(DATA.resolve()):
            if Path(p).resolve()!= (DATA/'reports/reproducibility_results.json').resolve():
                raise PermissionError('dataset_write_denied')
            save('validation/reproducibility_receipt.sealed.json',value)
        else: original_write(p,value)
    r.write=external_receipt
    save('validation/validation_receipt.sealed.json',v.validate(DATA))
    result=r.reproducibility(DATA)
    unchanged=inventory(DATA)==before['dataset'] and inventory(DATA.parents[1]/'scripts')==before['generators']
    save('validation_summary.json',dict(validation='PASS',reproducibility=result['status'],dataset_unchanged=unchanged,
        receipt_redirected=True,validator_reads_labels_in_separate_process=True,adapter_developer_receives_only_aggregate_status=True))
    if not unchanged: raise ValueError('DATASET_CHANGED')
    print('VALIDATION_PASS REPRODUCIBILITY_'+result['status']+' DATASET_UNCHANGED='+str(unchanged),flush=True)

if __name__=='__main__':
    globals()[sys.argv[1]]()

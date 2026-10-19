"""Truth-free capability metadata from the declared native field profiles."""
import collections
import json
from .runtime import INPUT, OUT, EXPECTED, read, save


def build():
    if (OUT/'gt_access.json').exists():
        raise ValueError('metadata_must_precede_unseal')
    caps=read(OUT/'source_capabilities.json')
    # session_id is an authentication identity here, not a network session.
    paths={
        ('authentication','Auth Session'):['logon_id','session_id'],
        ('authentication','Network Session'):['connection_id'],
        ('firewall','Network Session'):['connection_id','session_id'],
        ('edr','File'):['file_path','file_hash'],
        ('ids','HTTP'):['http/http_method','http/url'],
    }
    data=collections.defaultdict(list)
    for line in INPUT.open(encoding='utf8'):
        row=json.loads(line);data[row['source_type']].append(row['event'])
    def present(raw,path):
        for key in path.split('/'):
            if not isinstance(raw,dict): return False
            raw=raw.get(key)
        return raw not in (None,'')
    for source in caps:
        name=source['source'];count=EXPECTED[name]
        for family,cap in source['capabilities'].items():
            pp=paths.get((name,family),[p.lstrip('/') for p in cap['raw_paths']])
            n=sum(any(present(r,p) for p in pp) for r in data[name])
            extension=cap['capability_class']=='FIXTURE_EXTENSION'
            cap.update(observed_count=n,raw_paths=['/'+p for p in pp],
                value='FIXTURE_EXTENSION' if n and extension else 'YES' if n==count else 'PARTIAL' if n else 'NO',
                capability_class='FIXTURE_EXTENSION' if n and extension else 'BASE' if n==count else 'CONDITIONAL' if n else 'NOT_OBSERVABLE',
                states=dict(OBSERVABLE_AND_PRESENT=n,OBSERVABLE_BUT_MISSING=count-n if n else 0,
                    NOT_OBSERVABLE=0 if n else count,OBSERVABLE_AND_CONFLICTING=0))
            cap['scope']='dataset-observed profile only; no universal vendor capability claim'
    save('source_capabilities.json',caps)
    extensions=[dict(source=c['source'],capability=k,**v) for c in caps for k,v in c['capabilities'].items()
        if v['capability_class']=='FIXTURE_EXTENSION']
    extensions += [dict(source=s,capability=k,capability_class='FIXTURE_EXTENSION',
        detail=detail) for s,k,detail in [
            ('authentication','cross_sensor_auth_session','raw session/logon IDs are base observations; cross-sensor alignment is simulation instrumentation'),
            ('edr','cross_sensor_auth_session','cross-sensor logon alignment is simulation instrumentation'),
            ('host_audit','cross_sensor_auth_session','cross-sensor session alignment is simulation instrumentation'),
            ('firewall','cross_sensor_network_session','native session ID is source-local; shared connection token is simulation instrumentation'),
        ]]
    save('fixture_extension_capabilities.json',extensions)
    save('observability_state_consumption.json',dict(
        metadata_states=['NOT_OBSERVABLE','OBSERVABLE_BUT_MISSING','OBSERVABLE_AND_PRESENT','OBSERVABLE_AND_CONFLICTING'],
        conflicts='No within-record contradictory normalized identity was accepted; pair disagreements are separate scorer diagnostics, not missingness.',
        consumer_gap='Frozen state_for sees absent canonical scalar as MISSING and does not consume source capability metadata. Extra identity entities may support a dimension even when its primary scalar is missing.',
        numeric_effect='V5 aggregate excludes both MISSING and UNOBSERVABLE from positive/negative support. No missing-as-zero penalty repair was made.',
        formula_changed=False,source_independence='unknown; no cross-sensor complement bonus'))
    print('SOURCE_METADATA_COMPLETE')


if __name__=='__main__': build()

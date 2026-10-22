"""Explicit native alert profiles and trace-only JSONL envelopes.

This profile covers the observed simulation schemas, not every product bearing
these names. Wrapper locators never enter CanonicalAlert or entity identity.
Additional identities reuse SESSION with disjoint, declared typed scopes.
"""
from app.models import SourceType, ProcessRef, EntityType
from app.models.base import resolve_pointer
from app.entities.normalization import text, integer, ip, timestamp
from app.utils.stable_id import canonical_json
from .base import AlertAdapter, pick, reject_truth
from .suricata import SuricataAdapter

SOURCE_TYPES = dict(ids=SourceType.SURICATA,waf=SourceType.WAF,edr=SourceType.EDR,
                    firewall=SourceType.OTHER,authentication=SourceType.OTHER,host_audit=SourceType.OTHER)
PATHS = {
 'waf':dict(src_ip='client_ip',dst_ip='server_ip',src_port='client_port',dst_port='server_port',
            host='server_host',domain='host',url='uri',session='request_id',rule_id='rule_id',signature='rule_name'),
 'edr':dict(host='hostname',account='user',session='logon_id',src_ip='src_ip',dst_ip='dst_ip',
            src_port='src_port',dst_port='dst_port',file='file_path',command='command_line',alert_type='operation'),
 'firewall':dict(src_ip='src_ip',dst_ip='dst_ip',src_port='src_port',dst_port='dst_port',
                 session='session_id',sensor='device_id',rule_id='rule_id',signature='rule_name'),
 'authentication':dict(host='host',account='account',src_ip='source_ip',dst_ip='host_ip',
                       src_port='source_port',dst_port='destination_port',session='session_id',alert_type='operation'),
 'host_audit':dict(host='host',account='account',session='session',file='file_path',command='command',alert_type='operation'),
}
EXTRA_FIELDS=('protocol','proto','flow_id','connection_id','session_id','logon_id','request_id','application_session_id',
 'application_id','method','http/http_method','http/status','http/http_user_agent','query','status_code','user_agent',
 'action','direction','operation','audit_type','audit_id','file_hash','host_ip','host_id','server_host_id',
 'worker_process_id','worker_process_start_time','process_id','process_start_time','parent_process_id',
 'parent_process_start_time','pid','ppid','realm','service','result','authentication_method',
 'observation_sequence','session_observation_sequence','request_object_id','response_object_id','tx_id')

class MultiSourceAdapter(AlertAdapter):
    def __init__(self,config,settings,native_source):
        super().__init__(config,settings)
        if settings.format_profile!='multisource_native_v1' or native_source not in SOURCE_TYPES:
            raise ValueError('unsupported_multisource_profile')
        self.native_source=native_source

    def convert(self, raw):
        # File/batch ingress and direct record conversion share the same path.
        if isinstance(raw, dict) and 'event' in raw:
            return self.convert_record(raw)
        return super().convert(raw)

    def extract(self,raw):
        source=self.native_source
        if source=='ids':
            # Invoke the EVE extractor without changing historical EVE behavior.
            facts,pointers,context=SuricataAdapter.extract(self,raw)
        else:
            if raw.get('source_type')!=source: raise ValueError('native_source_routing_mismatch')
            facts=dict(timestamp=self.parse_time(raw.get('timestamp')),source_type=SOURCE_TYPES[source])
            pointers=dict(timestamp='/timestamp',source_type='/source_type')
            for name,path in PATHS[source].items(): pick(raw,facts,pointers,name,'/'+path)
            if source=='waf' and facts.get('url') and raw.get('query'):
                # URI path and query are separate observed HTTP components.
                # Never drop a query or combine two disagreeing query strings.
                if '?' in facts['url']:
                    if facts['url'].split('?',1)[1]!=raw['query']: raise ValueError('conflicting_http_query')
                else: facts['url'] += '?' + raw['query']
            pick(raw,facts,pointers,'source_record_id','/event_id') # Native ID, never wrapper ID.
            for name in ('process','parent_process'):
                if source not in ('edr','host_audit','authentication'): continue
                prefix='' if name=='process' else 'parent_'
                pidkey=('pid' if name=='process' else 'ppid') if source=='host_audit' else prefix+'process_id'
                keys=dict(pid=pidkey,start_time=prefix+'process_start_time',name=prefix+'process_name',
                          guid=prefix+'process_guid',instance_id=prefix+'process_instance_id')
                keys['executable']='executable' if name=='process' else 'parent_executable'
                values={k:raw[p] for k,p in keys.items() if raw.get(p) not in (None,'')}
                if not any(k in values for k in ('pid','name','executable','guid','instance_id')): continue
                if 'pid' in values: values['pid']=integer(values['pid'])
                if 'start_time' in values: values['start_time']=self.parse_time(values['start_time'])
                facts[name]=ProcessRef(**values)
                pointers[name]='/'+next(p for k,p in keys.items() if k in values)
                pointers.update({name+'.'+k: '/'+keys[k] for k in values})
            context=dict(raw_severity=raw.get('severity'),vendor_category=raw.get('category'),rule_groups=[])
            if source=='waf' and raw.get('worker_process_id') is not None and raw.get('worker_process_start_time'):
                facts['process']=ProcessRef(pid=integer(raw['worker_process_id']),start_time=self.parse_time(raw['worker_process_start_time']))
                pointers['process']='/worker_process_id'
                pointers['process.pid']='/worker_process_id'
                pointers['process.start_time']='/worker_process_start_time'
        for path in EXTRA_FIELDS:
            try: value=resolve_pointer(raw,'/'+path)
            except ValueError: continue
            if value not in (None,''): pointers.setdefault('native.'+path,'/'+path)
        return facts,pointers,context

    def convert_record(self,record):
        if type(record) is not dict or record.get('source_type')!=self.native_source or type(record.get('event')) is not dict:
            raise ValueError('invalid_native_envelope')
        reject_truth(record)
        # Native timestamp is present in this profile. A wrapper time, if supplied,
        # must agree, not silently rewrite the device's observation time.
        raw=record['event']
        if 'timestamp' in record and self.parse_time(record['timestamp'])!=self.parse_time(raw.get('timestamp')):
            raise ValueError('wrapper_native_timestamp_conflict')
        return self.convert(raw)

def additional_entities(alert,settings):
    """Yield role/type/normalized value/pointer/scope for whitelisted raw fields.

    Scope encodes identity kind to prevent request/auth/network/flow collisions.
    No occurrence is manufactured for an absent or unknown field.
    """
    raw=alert.raw_alert
    network=settings.network_namespace or alert.source_namespace
    host_scope=canonical_json(dict(asset_namespace=settings.asset_namespace or alert.source_namespace,host=alert.host)) if alert.host else alert.source_namespace
    source=raw.get('source_type','ids' if raw.get('event_type')=='alert' else None)
    if source not in SOURCE_TYPES: return
    host_ip=raw.get('host_ip')
    if host_ip:
        yield 'monitored_host_ip',EntityType.IP,ip(host_ip),'/host_ip',network
    file_hash=text(raw.get('file_hash'))
    if file_hash:
        # Hash algorithm is not guessed. Same native hash bytes within the
        # same host form a file identity, distinct from a path identity.
        yield 'file',EntityType.FILE,file_hash,'/file_hash',canonical_json(dict(file_hash_host_scope=host_scope))
    # Identity is never based on event_id, a locator, a field's physical order,
    # or an artificial flow derived from the endpoint tuple.
    bindings=[('flow_id','flow',network),('connection_id','network_session',network)]
    if source=='waf':
        bindings += [('request_id','request',host_scope),('application_session_id','application_session',host_scope)]
    elif source=='edr':
        bindings += [('request_id','request',host_scope),('logon_id','auth_session',host_scope)]
    elif source=='authentication':
        bindings += [('session_id','auth_session',host_scope),('logon_id','auth_session',host_scope)]
    elif source=='host_audit': bindings += [('session','auth_session',host_scope)]
    elif source=='firewall': bindings += [('session_id','network_session',network)]
    for key,kind,base in bindings:
        value=text(raw.get(key))
        if value is not None:
            scope=canonical_json(dict(identity_kind=kind,namespace=base))
            yield 'session',EntityType.SESSION,value,'/'+key,scope

def session_scope(alert,settings):
    """Primary scalar SESSION uses exactly the same typed scope as extra refs."""
    raw=alert.raw_alert;source=raw.get('source_type')
    host=canonical_json(dict(asset_namespace=settings.asset_namespace or alert.source_namespace,host=alert.host)) if alert.host else alert.source_namespace
    kind='request' if source=='waf' else 'network_session' if source=='firewall' else 'auth_session'
    base=(settings.network_namespace or alert.source_namespace) if kind=='network_session' else host
    return canonical_json(dict(identity_kind=kind,namespace=base))

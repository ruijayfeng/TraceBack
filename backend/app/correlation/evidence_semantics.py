"""Five states over existing canonical facts; never infers source capabilities."""
from .formula_v5 import aggregate

FIELDS={'IP':('src_ip','dst_ip'),'HOST':('host',),'ACCOUNT':('account',),
        'SESSION':('session',),'PROCESS':('process','parent_process'),
        'DOMAIN':('domain',),'URL':('url',),'FILE':('file',),'COMMAND':('command',)}
SCOPES={'IP':'network_namespace','HOST':'asset_namespace','ACCOUNT':'account_realm',
        'SESSION':'session_scope','PROCESS':'asset_namespace','FILE':'asset_namespace','COMMAND':'asset_namespace'}


def state_for(feature, a, b, settings, audit):
    if feature['state']=='CONTRADICTED': return 'OBSERVED_CONTRADICTION'
    if feature['strength']>0: return 'OBSERVED_SUPPORT'
    name=feature['name']; kind=name.removeprefix('entity.')
    if kind in FIELDS:
        if name in audit.get('suppressed_dimensions',[]): return 'UNOBSERVABLE'
        if not all(any(getattr(x,k) is not None for k in FIELDS[kind]) for x in (a,b)): return 'MISSING'
        scope=SCOPES.get(kind)
        # Canonical fallback source-scoping remains observable within a source;
        # cross-source identity with undeclared scope cannot be compared.
        if scope and a.source_namespace!=b.source_namespace and any(
            getattr(settings[x.source_namespace],scope) is None for x in (a,b)):
            return 'UNOBSERVABLE'
        return 'OBSERVED_NEUTRAL'
    if name=='metadata.detector_identity':
        return 'OBSERVED_NEUTRAL' if all(x.category.value!='unknown' or any(
            getattr(x,k) is not None for k in ('rule_id','signature')) for x in (a,b)) else 'MISSING'
    if name=='topology.network_continuity':
        if audit.get('network_diagnostic') in ('local_host_observation','attested_relation_consumes_endpoint_bridge'):
            return 'UNOBSERVABLE'
        return 'OBSERVED_NEUTRAL' if all(x.src_ip and x.dst_ip for x in (a,b)) else 'MISSING'
    if name=='topology.attested_relation': return 'OBSERVED_NEUTRAL' if a.relations or b.relations else 'MISSING'
    if feature['family']=='source': return 'UNOBSERVABLE' if feature['state']=='UNOBSERVABLE' else 'OBSERVED_NEUTRAL'
    return 'OBSERVED_NEUTRAL'


def repair(features, scorer, a, b, audit, policy, values, conflicts):
    features=[{**f,'state':state_for(f,a,b,scorer.settings,audit)} for f in features]
    result=aggregate(features,policy,hard=bool(conflicts['hard'] or conflicts.get('reversed_relation')),
        duplicate_risk=audit['duplicate_observation_risk'],duplicate=values['duplicate'])
    return dict(features=features,policy=policy,duplicate=values['duplicate'],**result)

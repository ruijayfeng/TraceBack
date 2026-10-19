"""Candidate graph with unchanged controlled-component protections.

Historical CorrelationEdge/ChainEdge parsers intentionally reject schema 5.2.
This opt-in graph adapter reuses target/hard-guard and node constructors. It
does not install candidate objects in a production SnapshotStore or API.
"""
from itertools import product
from app.correlation.conflicts import group_targets, targets, pair_conflicts
from app.chains.nodes import maximum_severity, build_nodes
from app.models import Incident
from app.utils.stable_id import id_for
from app.correlation.index import event_microseconds


def reconstruct(index,edges,scorer,policy):
    cfg=scorer.algorithm.clustering
    ordered=sorted((e for e in edges if e.score>=cfg.edge_threshold),key=lambda e:(-e.score,e.edge_id))
    components={r:{r} for r in index.representatives};owners={r:r for r in components}
    target_sets={r:{t.key for t in group_targets(r,index,scorer.settings)} for r in components}
    diagnostics=[];hard_cache={}
    def raw_members(reps):return sorted(i for r in sorted(reps) for i in index.groups[r])
    def propagation(e):
        d=e.support.direction
        # Only the field-proven access pivot can act as a cross-target bridge.
        return d.status=='DERIVED_VERIFIED_DIRECTION' and any(
            c['channel']=='host_to_login_source' for c in d.forward_evidence+d.reverse_evidence)
    def hard(left,right):
        for a,b in product(raw_members(left),raw_members(right)):
            key=tuple(sorted((a,b)))
            if key not in hard_cache:
                x,y=index.alerts[a],index.alerts[b];rs,_=scorer.verify_relations(x,y)
                hard_cache[key]=pair_conflicts(x,y,index,scorer.algorithm,scorer.settings,rs,
                    sorted(set(x.entity_ids)&set(y.entity_ids)),[])['hard']
            if hard_cache[key]:return True
        return False
    while True:
        changed=False;seen=set()
        for edge in ordered:
            l,r=owners[edge.source_alert_id],owners[edge.target_alert_id]
            if l==r:continue
            left,right=components[l],components[r];signature=tuple(sorted((l,r)))
            if signature in seen:continue
            seen.add(signature)
            supports=[e for e in ordered if (e.source_alert_id in left and e.target_alert_id in right or
                e.source_alert_id in right and e.target_alert_id in left)]
            # Distinct representative pairs only; one selected support per pair.
            support_count=len({tuple(e.support.support_key) for e in supports})
            explicit=any(propagation(e) or e.support.baseline['direct_support']>0 for e in supports)
            sizes=sorted((len(left),len(right)))
            needed=cfg.bridge_min_edges_between_singletons if sizes==[1,1] else (
                cfg.bridge_min_edges_with_singleton if sizes[0]==1 else cfg.bridge_min_edges_between_non_singletons)
            members=raw_members(left|right);span=(max(index.times[i] for i in members)-min(index.times[i] for i in members))/1e6
            lt=set().union(*(target_sets[i] for i in left));rt=set().union(*(target_sets[i] for i in right))
            bridge=False
            for e in supports:
                if not propagation(e) and not e.support.baseline['direct_support']:continue
                a,b=[index.alerts[i] for i in e.support.support_pair]
                at={t.key for t in targets(a,index,scorer.settings)};bt={t.key for t in targets(b,index,scorer.settings)}
                bridge|=bool(at and bt and at!=bt)
            rejects=[]
            if hard(left,right):rejects.append('component_hard_conflict')
            if span>cfg.max_incident_span_seconds:rejects.append('max_incident_span_seconds')
            if sum(sizes)>cfg.max_representatives:rejects.append('max_representatives')
            if lt and rt and lt!=rt and not bridge:rejects.append('target_set_without_propagation')
            if support_count<needed and not (cfg.permit_explicit_relation_single_bridge and explicit):rejects.append('independent_support_count')
            diagnostics.append(dict(stage='clustering',support_key=edge.support.support_key,component_sizes=sizes,
                independent_support_count=support_count,required=needed,decision='reject' if rejects else 'accept',rejection_codes=rejects))
            if rejects:continue
            root=min(l,r);components[root]=left|right
            del components[max(l,r)]
            for rep in components[root]:owners[rep]=root
            changed=True
        if not changed:break
    incidents=[];nodes=[];node_by_alert={};incident_by_alert={}
    for reps in sorted(components.values(),key=lambda x:sorted(x)):
        members=raw_members(reps)
        es=[e for e in edges if e.source_alert_id in reps and e.target_alert_id in reps]
        data=dict(alert_ids=members,start_time=min(index.alerts[i].timestamp for i in members),
            end_time=max(index.alerts[i].timestamp for i in members),severity=maximum_severity(index.alerts[i] for i in members),
            entity_ids=sorted({eid for i in members for eid in index.alerts[i].entity_ids}),correlation_edge_ids=sorted(e.edge_id for e in es))
        data['incident_id']=id_for('Incident',data);inc=Incident.model_validate(data)
        incidents.append(inc);ns=build_nodes(inc,index,scorer);nodes.extend(ns)
        for n in ns:
            for aid in n.alert_ids:node_by_alert[aid]=n;incident_by_alert[aid]=inc.incident_id
    chains=[];adjacency={n.node_id:set() for n in nodes}
    def reachable(a,b):
        stack=[a];seen=set()
        while stack:
            n=stack.pop()
            if n==b:return True
            if n not in seen:seen.add(n);stack.extend(adjacency[n])
        return False
    for e in sorted(edges,key=lambda e:(-e.support.direction.direction_confidence,e.edge_id)):
        d=e.support.direction
        if d.status!='DERIVED_VERIFIED_DIRECTION' or e.score<scorer.algorithm.chain.edge_threshold:continue
        a,b=d.source_alert_id,d.target_alert_id
        if incident_by_alert[a]!=incident_by_alert[b]:continue
        src,dst=node_by_alert[a],node_by_alert[b]
        if src.node_id==dst.node_id:continue
        if (event_microseconds(src.end_time)-event_microseconds(dst.start_time))/1e6>policy['clock_skew_seconds']:continue
        if reachable(dst.node_id,src.node_id):
            diagnostics.append(dict(stage='dag',edge_id=e.edge_id,decision='reject_cycle'));continue
        relation='ACCOUNT_PIVOT' if propagation(e) else 'DERIVED_OPERATION'
        data=dict(incident_id=src.incident_id,source_node_id=src.node_id,target_node_id=dst.node_id,relation_type=relation)
        chains.append(dict(schema_version='5.2-candidate',edge_id=id_for('ChainEdge',data),**data,
            alert_ids=sorted(e.support.support_pair),correlation_edge_ids=[e.edge_id],
            correlation_score=e.score,direction_confidence=d.direction_confidence,
            direction_evidence=d.model_dump(mode='json'),score_breakdown=e.support.score_breakdown,
            reasons=[dict(rule_id='candidate.direction.two_consistent_operation_role_channels',
                alert_ids=sorted(e.support.support_pair),direction_reason=d.direction_reason)]))
        adjacency[src.node_id].add(dst.node_id)
    assert len(node_by_alert)==len(index.alerts)
    return incidents,nodes,chains,diagnostics

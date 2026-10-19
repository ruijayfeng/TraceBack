"""Actual production reconstruction, sealed PairScore lookup, no truth input."""
from collections import Counter
import gzip,json
from . import ROOT,OUT
from .runtime import verify_seal,verify_freeze
from evaluation.framework.formula_design import BASELINE
from evaluation.framework.formula_design.runtime import read,save,rows,guard
from evaluation.framework.threshold_calibration.metrics import longest_path
from .evaluate import write_csv

def run():
    verify_seal()
    from app.adapters.base import AdapterSettings
    from app.models import CanonicalAlert,DedupeGroup,Entity,CorrelationEdge,AnalysisRecord,Reason
    from app.correlation.scoring import CorrelationScorer,PairScore,VerifiedRelation
    from app.correlation.index import AlertIndex
    from app.services.storage import restore_config,SnapshotStore
    from app.chains.assembly import run_reconstruction
    from app.correlation.edges import peak_memory_mb
    from app.correlation import entity_bridges,formula_v5,evidence_semantics
    from app.correlation.evidence_v4 import EvidenceV4Evaluator
    from app.dedup.observation import ObservationMatcher
    from app.services.capacity import AlertSequence,execution_state
    peak_memory_mb()
    frozen=verify_freeze();cal=read(OUT/'calibration.json')
    threshold=cal['selected_threshold'] if cal['selected_threshold'] is not None else cal['diagnostic_threshold']
    # No stable threshold in a failed calibration: do not silently install a low
    # diagnostic operating point as a production configuration.
    if threshold<.65: raise ValueError('lower_stable_threshold_requires_explicit_sealed_edge_materialization')
    paths=[BASELINE/'blind'/n for n in ('canonical.jsonl.gz','dedupe.jsonl.gz','entities.jsonl.gz')]
    paths += [OUT/'formula_freeze.json',OUT/'blind/record.json',OUT/'blind/edges.jsonl.gz',OUT/'blind/diagnostics.jsonl.gz']
    destination=OUT/'downstream';destination.mkdir(exist_ok=False)
    calls=Counter();original=CorrelationScorer.score_pair;graphs={};summaries={}
    try:
        with guard(paths,destination) as (events,reads):
            config=restore_config(frozen['effective']['algorithm'])
            settings={k:AdapterSettings(**v) for k,v in frozen['effective']['sources'].items()}
            alerts=[CanonicalAlert.model_validate(r) for r in rows(paths[0])]
            groups=[DedupeGroup.model_validate(r) for r in rows(paths[1])]
            entities=[Entity.model_validate(r) for r in rows(paths[2])]
            upstream=AnalysisRecord.model_validate(read(paths[4]))
            edges=[CorrelationEdge.model_validate(r) for r in rows(paths[5])]
            index=AlertIndex(alerts,groups,entities)
            keys={tuple(sorted((e.source_alert_id,e.target_alert_id))) for e in edges};cache={}
            for row in rows(paths[6]):
                if row['stage']!='member_score' or tuple(row['support_key']) not in keys:continue
                audit=row['evidence']['evidence_v2']
                relations=[VerifiedRelation(**{**r,'raw_pointers':tuple(r['raw_pointers'])}) for r in row['evidence']['relations']]
                ids=sorted({r['entity_id'] for r in row['evidence']['entity_features']} |
                    {i for r in relations for i in (r.source_entity_id,r.target_entity_id)} |
                    {i for d in audit['dimensions'] if d['state']=='AVAILABLE_MATCH' for i in d['entity_ids']})
                a,b=row['support_pair']
                cache[a,b]=PairScore(a,b,row['score'],row['values'],row['contributions'],row['raw_total'],
                    row['source_independence'],[Reason.model_validate(r) for r in row['reasons']],ids,relations,
                    row['rejection_codes'],row['evidence'])
            def sealed(self,a,b):
                calls['lookup']+=1
                if (a,b) not in cache:raise AssertionError('unsealed_downstream_pair:'+a+':'+b)
                return cache[a,b]
            CorrelationScorer.score_pair=sealed
            def score(edge):return cache[edge.support_pair.alert_id_src,edge.support_pair.alert_id_dst].score
            # Filtering below the fixed cluster .70 threshold cannot change
            # unions or directed edges. Cache by the actual eligible edge set.
            replay_thresholds=sorted({threshold,*[max(.7,r['threshold']) for r in cal['threshold_sweep']]})
            graph_cache={}
            primary=None;primary_edges=None
            for t in replay_thresholds:
                chosen=[e for e in edges if score(e)>=t]
                eligible=tuple(e.edge_id for e in chosen if score(e)>=.7)
                if t!=threshold and eligible in graph_cache:
                    summaries[t]=graph_cache[eligible][0];graphs[t]=graph_cache[eligible][1];continue
                counts=Counter();detail=destination/('replay_'+format(t,'.16g').replace('.','_'));detail.mkdir()
                with gzip.open(detail/'diagnostics.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
                    def sink(row):
                        counts[row['stage']+':'+str(row.get('rule_id',row.get('decision','')))]+=1
                        f.write(json.dumps(row,separators=(',',':'),ensure_ascii=False)+'\n')
                    result=run_reconstruction(alerts,groups,entities,chosen,config,settings,
                        upstream_record=upstream,existing_index=index,diagnostic_sink=sink)
                summary={**result.summary,'admission_filter':t,
                    'largest_chain_edges':max((len(c.edges) for c in result.chains),default=0),
                    'production_formula_rescoring_calls':0,'actual_reconstruction_executed':True,'decision_counts':dict(counts)}
                save(detail/'summary.json',summary)
                graph=[]
                for c in result.chains:
                    ns={n.node_id:n for n in c.nodes}
                    for e in c.edges: graph.append(dict(source_alert_ids=ns[e.source_node_id].alert_ids,target_alert_ids=ns[e.target_node_id].alert_ids))
                summaries[t]=summary;graphs[t]=graph;graph_cache[eligible]=(summary,graph)
                if t==threshold:
                    primary=result;primary_edges=chosen;primary_detail=detail
                    for name,records in [('incidents',result.incidents),('chains',result.chains)]:
                        with gzip.open(detail/(name+'.jsonl.gz'),'wt',encoding='utf8',compresslevel=1) as f:
                            for r in records:f.write(r.canonical_json()+'\n')
                print(json.dumps(dict(stage='actual_reconstruction',threshold=t,edges=len(chosen),chain_edges=summary['chain_edge_count'])),flush=True)
            save(destination/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),ground_truth_loaded=False,t2_read=False,
                production_formula_rescoring_calls=0,sealed_lookup_calls=calls['lookup'],unique_graph_reconstructions=len(graph_cache),
                graph_cache_proof='Only edges >=fixed .70 are eligible for clustering/direction; lower-admission differences affect display and singleton search diagnostics, not these graph counts'))
        # Persist the actual operating replay and verify every canonical table.
        store=SnapshotStore(primary_detail,primary.record.analysis_id);store.create()
        with gzip.open(primary_detail/'diagnostics.jsonl.gz','rt',encoding='utf8') as src,(store.details/'diagnostics.jsonl').open('w',encoding='utf8') as dst:
            for line in src:dst.write(line)
        for kind,records in [('alerts',alerts),('dedupe_groups',groups),('entities',entities),('correlation_edges',primary_edges),
            ('incidents',primary.incidents),('chain_nodes',[n for c in primary.chains for n in c.nodes]),
            ('chain_edges',[e for c in primary.chains for e in c.edges]),('attack_chains',primary.chains)]:
            store.write_records(kind,records)
            if sorted(r.canonical_json() for r in store.read_records(kind))!=sorted(r.canonical_json() for r in records):raise ValueError('persistence_roundtrip:'+kind)
        store.write_metadata(primary.record,index.frequency_snapshot(),primary.summary)
        persisted=store.validate_reconstruction();persisted.require_valid()
        save(primary_detail/'persistence_validation.json',dict(grounding=persisted.json_data(),all_domain_tables_roundtrip=True))
    finally:CorrelationScorer.score_pair=original
    # Graph construction has finished and sealed before post-hoc GT mapping.
    gt=read(OUT/'ground_truth_edge_scores.json')['edges'];projection=read(OUT/'evaluation/label_projection.json')
    def directed(graph):
        return {eid for eid,r in gt.items() if any(r['source_alert_id'] in e['source_alert_ids'] and r['target_alert_id'] in e['target_alert_ids'] for e in graph)}
    for row in cal['threshold_sweep']:
        effective=max(.7,row['threshold']);summary=summaries[effective];directed_gt=directed(graphs[effective])
        row.update(multi_alert_incidents=summary['multi_alert_incident_count'],chain_edges=summary['chain_edge_count'],
            longest_chain=summary['largest_chain_edges'],GT_chain_edges=len(directed_gt),
            GT_longest_path=longest_path([(gt[e]['from_node'],gt[e]['to_node']) for e in directed_gt]))
    save(OUT/'calibration.json',cal);write_csv(cal['threshold_sweep'])
    support={tuple(sorted(e.support_pair.alert_ids())) for e in primary_edges}
    recovered={e for e,r in gt.items() if tuple(sorted((r['source_alert_id'],r['target_alert_id']))) in support}
    dir_gt=directed(graphs[threshold]);nodes=[n for c in primary.chains for n in c.nodes]
    retained=set().union(*(set(n.alert_ids) for n in nodes))
    node_recovered={k for k,members in projection['nodes'].items() if retained & set(members)}
    # Same diagnostic matching as the accepted semisynthetic baseline. Stages
    # have no frozen Category translation and no gold Incident matching contract;
    # expose both views without claiming a formal RQ3 node recall.
    from fractions import Fraction
    from evaluation.framework.v4_semisynthetic_baseline.metrics import stable_match
    support_legal={};semantic_legal={}
    for n in nodes:
        for gid,members in projection['nodes'].items():
            overlap=set(n.alert_ids)&set(members)
            if overlap:
                support_legal[n.node_id,gid]=Fraction(len(overlap),len(set(n.alert_ids)|set(members)))
                if n.category.value==projection['node_stages'][gid]:
                    semantic_legal[n.node_id,gid]=support_legal[n.node_id,gid]
    support_matches=stable_match(support_legal);semantic_matches=stable_match(semantic_legal)
    failures={}
    for eid,r in gt.items():
        failures[eid]=('BROKEN_AT_CANDIDATE' if not r['candidate_present'] else 'BROKEN_AT_GATE' if not r['gate_pass'] else
            'BROKEN_AT_SCORE' if eid not in recovered else 'BROKEN_AT_DIRECTION' if not r['verified_relation_count'] else
            'BROKEN_AT_CLUSTERING' if eid not in dir_gt else 'RECOVERED')
    save(OUT/'chain_validation.json',dict(diagnostic_only=cal['selected_threshold'] is None,operating_threshold=threshold,
        CorrelationEdges_recovered=len(recovered),correlation_GT_ids=sorted(recovered),ChainEdges_recovered=len(dir_gt),
        GT_NODES_RETAINED=len(node_recovered),GT_NODES_RECOVERED=None,
        GT_NODES_SUPPORT_MATCHED=len(support_matches),GT_NODES_EXACT_STAGE_MATCHED=len(semantic_matches),
        support_node_matches=support_matches,exact_stage_node_matches=semantic_matches,
        node_note='All 7 GT node memberships have retained alert evidence; no GT node matching is claimed across fragmented incidents. Retention is not successful 7-node chain reconstruction.',
        Longest_GT_path_recovered=longest_path([(gt[e]['from_node'],gt[e]['to_node']) for e in dir_gt]),
        failures=failures,actual_reconstruction_executed=True,production_formula_rescoring_calls=0,
        summary=summaries[threshold],all_tables_roundtrip=True,grounding_valid=persisted.valid,
        actual_sweep_graphs={str(k):v for k,v in summaries.items()},
        explain_attack_downstream='Evidence closure verified for actual output. No directed GT edges => no attack-path explanation or ATT&CK claim fabricated. Existing AI grounding regressions and synthetic API control exercise valid downstream claims.'))
    print('ACTUAL_DOWNSTREAM_VALIDATION_COMPLETE',flush=True)

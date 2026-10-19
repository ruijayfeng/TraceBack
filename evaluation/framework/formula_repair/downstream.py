"""Actual reconstruction from sealed production edges, without rescoring.

The replay scorer only returns sealed PairScore objects. Missing scores fail;
no labels are available inside the reconstruction read guard.
"""
from collections import Counter
import gzip
import json
from . import ROOT,OUT
from .runtime import verify_seal
from evaluation.framework.formula_design import BASELINE
from evaluation.framework.formula_design.runtime import read,save,rows,guard
from evaluation.framework.threshold_calibration.metrics import longest_path


def run():
    verify_seal()
    from app.adapters.base import AdapterSettings
    from app.models import CanonicalAlert,DedupeGroup,Entity,CorrelationEdge,AnalysisRecord,Reason
    from app.correlation.scoring import CorrelationScorer,PairScore,VerifiedRelation
    from app.correlation.index import AlertIndex
    from app.services.storage import restore_config,SnapshotStore
    from app.chains.assembly import run_reconstruction
    from app.correlation.edges import peak_memory_mb
    from app.correlation import entity_bridges
    from app.correlation import formula_v5
    from app.correlation.evidence_v4 import EvidenceV4Evaluator
    from app.dedup.observation import ObservationMatcher
    from app.services.capacity import AlertSequence,execution_state
    peak_memory_mb()
    paths=[BASELINE/'blind'/n for n in ('canonical.jsonl.gz','dedupe.jsonl.gz','entities.jsonl.gz')]
    paths += [OUT/'formula_freeze.json',OUT/'blind/record.json',OUT/'blind/edges.jsonl.gz',OUT/'blind/diagnostics.jsonl.gz']
    destination=OUT/'downstream';destination.mkdir(exist_ok=False)
    replay_calls=Counter();summaries=[];all_results=[]
    original=CorrelationScorer.score_pair
    try:
        with guard(paths,destination) as (events,reads):
            frozen=read(paths[3]);config=restore_config(frozen['effective']['algorithm'])
            settings={k:AdapterSettings(**v) for k,v in frozen['effective']['sources'].items()}
            alerts=[CanonicalAlert.model_validate(r) for r in rows(paths[0])]
            groups=[DedupeGroup.model_validate(r) for r in rows(paths[1])]
            entities=[Entity.model_validate(r) for r in rows(paths[2])]
            upstream=AnalysisRecord.model_validate(read(paths[4]))
            edges=[CorrelationEdge.model_validate(r) for r in rows(paths[5])]
            index=AlertIndex(alerts,groups,entities)
            keys={tuple(sorted((e.source_alert_id,e.target_alert_id))) for e in edges}
            cache={}
            for row in rows(paths[6]):
                if row['stage']!='member_score' or tuple(sorted(row['support_key'])) not in keys:continue
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
                replay_calls['sealed_lookup']+=1
                if (a,b) not in cache:raise AssertionError('unsealed_downstream_pair:'+a+':'+b)
                return cache[a,b]
            CorrelationScorer.score_pair=sealed
            # Both are predeclared inspection points, not newly chosen thresholds.
            for threshold in (.65,.70):
                chosen=[e for e in edges if cache[e.support_pair.alert_id_src,e.support_pair.alert_id_dst].score>=threshold]
                counts=Counter()
                detail=destination/('replay_'+str(threshold).replace('.',''))
                detail.mkdir()
                with gzip.open(detail/'diagnostics.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
                    def sink(row):
                        counts[row['stage']+':'+str(row.get('rule_id',row.get('decision','')))]+=1
                        f.write(json.dumps(row,separators=(',',':'),ensure_ascii=False)+'\n')
                    result=run_reconstruction(alerts,groups,entities,chosen,config,settings,
                        upstream_record=upstream,existing_index=index,diagnostic_sink=sink)
                summary={**result.summary,'admission_filter':threshold,'clustering_threshold':.70,'chain_threshold':.70,
                    'largest_chain_edges':max((len(c.edges) for c in result.chains),default=0),
                    'production_formula_rescoring_calls':0,'actual_reconstruction_executed':True,
                    'decision_counts':dict(counts)}
                save(detail/'summary.json',summary)
                for name,records in [('incidents',result.incidents),('chains',result.chains)]:
                    with gzip.open(detail/(name+'.jsonl.gz'),'wt',encoding='utf8',compresslevel=1) as f:
                        for r in records:f.write(r.canonical_json()+'\n')
                summaries.append(summary);all_results.append((detail,chosen,result))
            save(destination/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),
                ground_truth_loaded=False,t2_read=False,production_formula_rescoring_calls=0,
                sealed_score_lookup_calls=replay_calls['sealed_lookup'],sealed_pair_cache_size=len(cache)))
        # Persistence operates on the already computed graph. No score function
        # or label input is needed to serialize/deserialize these domain records.
        for detail,chosen,result in all_results:
            store=SnapshotStore(detail,result.record.analysis_id);store.create()
            with gzip.open(detail/'diagnostics.jsonl.gz','rt',encoding='utf8') as source, (store.details/'diagnostics.jsonl').open('w',encoding='utf8') as target:
                for line in source:target.write(line)
            for kind,records in [('alerts',alerts),('dedupe_groups',groups),('entities',entities),
                ('correlation_edges',chosen),('incidents',result.incidents),
                ('chain_nodes',[n for c in result.chains for n in c.nodes]),
                ('chain_edges',[e for c in result.chains for e in c.edges]),('attack_chains',result.chains)]:
                store.write_records(kind,records)
                restored=list(store.read_records(kind))
                if sorted(r.canonical_json() for r in restored)!=sorted(r.canonical_json() for r in records):
                    raise ValueError('persistence_roundtrip:'+kind)
            store.write_metadata(result.record,index.frequency_snapshot(),result.summary)
            reload_grounding=store.validate_reconstruction()
            reload_grounding.require_valid()
            save(detail/'persistence_validation.json',dict(grounding=reload_grounding.json_data(),
                all_domain_tables_roundtrip=True,diagnostic_reference_exists=(store.details/'diagnostics.jsonl').exists(),
                production_formula_rescoring_calls=0))
    finally:
        CorrelationScorer.score_pair=original
    # Only now attach post-hoc GT witnesses to immutable downstream predictions.
    gt=read(OUT/'ground_truth_edge_scores.json')['edges']
    evaluated=[]
    for detail,chosen,result in all_results:
        support={tuple(sorted((e.support_pair.alert_id_src,e.support_pair.alert_id_dst))) for e in chosen}
        cor={eid for eid,r in gt.items() if tuple(sorted(r['support_pair'])) in support}
        directed=set();node_by={n.node_id:n for c in result.chains for n in c.nodes}
        for c in result.chains:
            for edge in c.edges:
                left,right=set(node_by[edge.source_node_id].alert_ids),set(node_by[edge.target_node_id].alert_ids)
                for eid,r in gt.items():
                    # Witness source/target orientation follows GT definitions,
                    # never sorted member ordering.
                    a,b=r.get('gt_source_alert_id'),r.get('gt_target_alert_id')
                    if a in left and b in right:directed.add(eid)
        evaluated.append(dict(threshold=result.summary.get('admission_filter',.65 if len(evaluated)==0 else .70),
            CorrelationEdges_recovered=len(cor),correlation_GT_ids=sorted(cor),
            ChainEdges_recovered=len(directed),directed_GT_ids=sorted(directed),
            Longest_GT_path_recovered=longest_path([(gt[e]['gt_from'],gt[e]['gt_to']) for e in directed]),
            summary=summaries[len(evaluated)]))
    primary=evaluated[0]
    save(OUT/'chain_validation.json',dict(primary=primary,replays=evaluated,
        actual_reconstruction_executed=True,production_formula_rescoring_calls=0,
        GT_edge_total=6,longest_GT_path_total=6,
        background_pollution=dict(status='NORMAL' if primary['summary']['max_incident_representatives']<=10 else 'OVER_CORRELATED',
            criterion='Conservative review flag: any >10 representatives; inspect exact sizes, not calibrated population limit.',
            total_edges=primary['summary']['correlation_edge_count'],
            multi_alert_incidents=primary['summary']['multi_alert_incident_count'],
            largest_incident=primary['summary']['max_incident_representatives'],
            largest_incident_original_alerts=primary['summary']['max_incident_original_alerts'],
            chain_edges=primary['summary']['chain_edge_count'],largest_chain=primary['summary']['largest_chain_edges']),
        synthetic_multistep_contract='backend/tests/test_formula_v5.py; integration control only, not frozen-dataset GT recovery',
        directed_recovery_rule='GT witness source member in source node and target member in target node; no correlation proxy'))
    print(json.dumps(read(OUT/'chain_validation.json')),flush=True)


if __name__=='__main__':run()

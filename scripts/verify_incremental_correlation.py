"""Independent Full/Increment validation and real, declared benchmark partitions.

No dependency audit is rerun or overwritten. Each performance path has its own
process, so Windows process peak working set is comparable. Source facts come
from the already verified immutable russellmitchell production snapshot.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))

from app.adapters.base import AdapterSettings
from app.chains.assembly import assemble_chain
from app.config import load_config
from app.correlation.edges import run_correlation, peak_memory_mb
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import deduplicate
from app.entities.extraction import extract_entities
from app.incidents.clustering import cluster_incidents
from app.incidents.triage import triage_singletons
from app.models import CanonicalAlert
from app.services.incremental import IncrementalService, pair_key
from app.services.incremental_dependencies import json_value
from app.services.storage import SnapshotStore, restore_config, atomic_json, file_digest
from app.utils.stable_id import canonical_json, content_digest


def emit(row):
    print(json.dumps(row,ensure_ascii=False,sort_keys=True),flush=True)


def semantic_receipt(records,candidates,outcomes=None):
    digests={kind:content_digest(sorted(canonical_json(json_value(row)) for row in rows))
        for kind,rows in records.items()}
    candidate_rows=[]
    if isinstance(candidates,dict):
        for key,state in sorted(candidates.items()):
            candidate_rows.append({'key':key,'priority':state['priority'],'channels':state['channels'],'evidence':state['evidence']})
    else:
        for pair in candidates:
            candidate_rows.append({'key':pair_key(pair.support_key),'priority':json_value(pair.priority),
                'channels':list(pair.channels),'evidence':[e.json_data() for e in pair.evidence]})
    digests['candidates']=content_digest(sorted(canonical_json(json_value(row)) for row in candidate_rows))
    if outcomes is None and isinstance(candidates,dict):
        outcomes={key:{'score':state['unrounded_score'],'support_pair':state['support_pair'],
            'accepted':state['edge_id'] is not None,'gate_passed':state['gate_passed'],'evidence_decision':state['decision']}
            for key,state in candidates.items()}
    if outcomes is not None:
        digests['correlation_scores_and_support']=content_digest(outcomes)
    return digests


def oracle(alerts,cfg,source):
    started=time.perf_counter()
    groups=deduplicate(alerts,cfg,source).groups
    extracted=extract_entities(alerts,source)
    outcomes={}
    def capture(row):
        if row['stage']=='correlation_decision':
            outcomes[pair_key(row['support_key'])]={'score':row['score'],'support_pair':row['support_pair'],
                'accepted':row['decision']=='accept','gate_passed':row['evidence_gate_passed'],
                'evidence_decision':row['evidence_decision']}
    cor=run_correlation(extracted.alerts,groups,extracted.entities,cfg,source,progress=emit,diagnostic_sink=capture)
    cor.outcomes=outcomes
    idx=AlertIndex(extracted.alerts,groups,extracted.entities)
    scorer=CorrelationScorer(idx,cfg,source,cor.record.config_hash)
    clustered=cluster_incidents(idx,cor.edges,scorer)
    incidents=triage_singletons(clustered.incidents,idx,cfg,cor.summary,search_complete=cor.record.is_complete)
    edge_map={e.edge_id:e for e in cor.edges}
    chains=[assemble_chain(i,idx,scorer,[edge_map[k] for k in i.correlation_edge_ids],support_cache=clustered.support_cache)
        for i in incidents]
    records={kind:[row.model_dump(mode='json') for row in values] for kind,values in
        {'alerts':extracted.alerts,'dedupe_groups':groups,'entities':extracted.entities,
         'correlation_edges':cor.edges,'incidents':incidents,'attack_chains':chains}.items()}
    return records,cor,idx,time.perf_counter()-started


def export_full(destination,records,cor,idx):
    store=SnapshotStore(destination,cor.record.analysis_id)
    for kind,rows in records.items():
        store.write_records(kind,rows)
    store.write_records('chain_nodes',[n for c in records['attack_chains'] for n in c['nodes']])
    store.write_records('chain_edges',[e for c in records['attack_chains'] for e in c['edges']])
    with store.diagnostics_writer() as sink:
        sink({'stage':'benchmark_full','scored_candidates':len(cor.candidates.pairs)})
    store.write_metadata(cor.record,idx.frequency_snapshot(),cor.summary)
    store.read_metadata()


def worker(args):
    folder=Path(args.destination).resolve()
    recipe=json.loads((folder/'recipe.json').read_text(encoding='utf-8'))
    cfg=restore_config(recipe['config_snapshot']['algorithm'])
    source={k:AdapterSettings(**v) for k,v in recipe['config_snapshot']['sources'].items()}
    all_alerts=[CanonicalAlert.model_validate_json(line) for line in (folder/'input.jsonl').read_text(encoding='utf-8').splitlines()]
    size=recipe['base_size']
    alerts=all_alerts[:size+args.batch]
    destination=folder/f'plus_{args.batch}'
    destination.mkdir(parents=True,exist_ok=True)
    started=time.perf_counter()
    if args.worker=='bootstrap':
        service=IncrementalService(folder/'base'/'workspace.duckdb',cfg,source,
            snapshot_root=folder/'base'/'snapshots',progress=emit)
        try:
            resumed=service.head is not None
            receipt=service.head if resumed else service.bootstrap(all_alerts[:size])
            service.store.db.execute('CHECKPOINT')
            records=service.records()
            digests=semantic_receipt({k:v for k,v in records.items() if k!='candidates'},records['candidates'])
            result={'receipt':receipt,'digests':digests,'end_to_end_seconds':None if resumed else time.perf_counter()-started,
                'resumed_committed_bootstrap':resumed,'peak_memory_mb':peak_memory_mb()}
        finally:
            service.close()
        atomic_json(folder/'bootstrap.json',result)
        return
    if args.worker=='full':
        records,cor,idx,compute=oracle(alerts,cfg,source)
        export_full(destination/'full_snapshot',records,cor,idx)
        elapsed=time.perf_counter()-started
        result={'digests':semantic_receipt(records,cor.candidates.pairs,cor.outcomes),
            'candidate_count':len(cor.candidates.pairs),'scored_pairs':len(cor.candidates.pairs),
            'incident_representatives_replayed':idx.N,'incident_count':len(records['incidents']),
            'canonical_count':len(alerts),'representative_count':idx.N,'compute_seconds':compute,
            'end_to_end_seconds':elapsed,'peak_memory_mb':peak_memory_mb(),
            'source_counts':dict(Counter(a.source_type.value for a in alerts))}
    else:
        path=destination/'increment'/'workspace.duckdb'
        path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(folder/'base'/'workspace.duckdb',path)
        service=IncrementalService(path,cfg,source,snapshot_root=destination/'increment'/'snapshots',progress=emit)
        # Restart and parent publication are measured separately; ingestion is
        # a pre-normalized canonical batch in both paths, no parser time hidden.
        restart=time.perf_counter()-started
        started=time.perf_counter()
        try:
            receipt=service.increment(all_alerts[size:size+args.batch])
            elapsed=time.perf_counter()-started
            records=service.records()
            digests=semantic_receipt({k:v for k,v in records.items() if k!='candidates'},records['candidates'])
            result={'digests':digests,'stats':receipt['stats'],'analysis_id':receipt['analysis_id'],
                'generation_id':receipt['generation_id'],'end_to_end_seconds':elapsed,
                'restart_seconds':restart,'peak_memory_mb':peak_memory_mb(),
                'idempotency_pass':service.increment(all_alerts[size:size+args.batch])['idempotent_replay']}
        finally:
            service.close()
    atomic_json(destination/(args.worker+'.json'),result)
    emit({'completed':args.worker,'batch':args.batch,'end_to_end_seconds':result['end_to_end_seconds']})


def run(args):
    folder=Path(args.destination).resolve()
    folder.mkdir(parents=True,exist_ok=True)
    parent=SnapshotStore(ROOT,args.source_analysis_id)
    record,_,_=parent.read_metadata()
    all_alerts=sorted(parent.read_records('alerts'),key=lambda a:(a.timestamp,a.alert_id))
    if args.base_size+1000>len(all_alerts):
        raise ValueError('benchmark_base_exceeds_available_population')
    alerts=all_alerts[:args.base_size+1000]
    recipe={'source_analysis_id':args.source_analysis_id,'source_dataset_digest':record.dataset_digest,
        'source_canonical_count':len(all_alerts),'base_size':args.base_size,'batch_sizes':[1,10,100,1000],
        'selection':'first base_size+1000 canonical alerts sorted by timestamp,alert_id; independent batches on same Base',
        'benchmark_population':'declared chronological real-data partition, not full-corpus throughput',
        'adapter_normalization':'reuse verified immutable canonical facts, excluded equally from both timed paths',
        'base_ids':[a.alert_id for a in alerts[:args.base_size]],
        'delta_ids':[a.alert_id for a in alerts[args.base_size:]],'config_snapshot':record.config_snapshot,
        'config_hash':record.config_hash,'algorithm_version':record.algorithm_version,
        'ground_truth_used':False,'ai_used':False}
    atomic_json(folder/'recipe.json',recipe)
    (folder/'input.jsonl').write_text(''.join(a.canonical_json()+'\n' for a in alerts),encoding='utf-8')
    script=Path(__file__).resolve()
    def execute(mode,batch):
        with (folder/f'{mode}_{batch}.log').open('w',encoding='utf-8') as handle:
            subprocess.run([sys.executable,str(script),'--destination',str(folder),'--worker',mode,'--batch',str(batch)],
                check=True,stdout=handle,stderr=subprocess.STDOUT)
    execute('bootstrap',0)
    rows=[]
    for batch in (1,10,100,1000):
        emit({'starting_real_batch':batch})
        execute('full',batch)
        execute('increment',batch)
        full=json.loads((folder/f'plus_{batch}'/'full.json').read_text(encoding='utf-8'))
        inc=json.loads((folder/f'plus_{batch}'/'increment.json').read_text(encoding='utf-8'))
        matched={k:full['digests'][k]==inc['digests'][k] for k in full['digests']}
        row={'batch_size':batch,'matches':matched,'equivalence':'PASS' if all(matched.values()) else 'FAIL',
            'full':full,'incremental':inc}
        rows.append(row)
        atomic_json(folder/'benchmark.json',rows)
        emit({'batch':batch,'equivalence':row['equivalence'],'full_seconds':full['end_to_end_seconds'],
            'incremental_seconds':inc['end_to_end_seconds'],'dependency_closure_ratio':inc['stats']['dependency_closure_ratio']})
        if row['equivalence']!='PASS':
            raise AssertionError('full_incremental_equivalence_failed')
    atomic_json(folder/'equivalence.json',{'FULL_INCREMENTAL_EQUIVALENCE':'PASS','rows':[{'batch_size':r['batch_size'],'matches':r['matches']} for r in rows]})


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination',default=str(ROOT/'outputs/incremental_correlation/production/real_benchmark'))
    parser.add_argument('--source-analysis-id',default='ana_c9d63511744137fb6fb34fce4d17a60796a62dfbb2291456cecf59c3b1d631fd')
    parser.add_argument('--base-size',type=int,default=2000)
    parser.add_argument('--worker',choices=['bootstrap','full','increment'])
    parser.add_argument('--batch',type=int,default=0)
    args=parser.parse_args()
    worker(args) if args.worker else run(args)

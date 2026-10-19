"""Execute the unchanged downstream on the actual empty 0.65 F2 edge set.

Lower-threshold formal V5 edge serialization is unavailable. Do not fabricate
ScoreBreakdown, bypass validation or call the old scorer with V5 scores.
"""
import gzip
import json
import sys

from . import ROOT, OUT
from .runner import verify_score_seal
from evaluation.framework.formula_design import BASELINE
from evaluation.framework.formula_design.runtime import read, save, rows, sha, guard


def run():
    verify_score_seal()
    sys.path.insert(0,str(ROOT/'backend'))
    from app.models import CanonicalAlert, DedupeGroup, Entity
    from app.adapters.base import AdapterSettings
    from app.services.storage import restore_config
    from app.correlation.scoring import CorrelationScorer
    from app.chains.assembly import run_reconstruction
    # Preload imports before the data read guard; then deny *all* data except
    # the frozen prediction inputs. No GT or t2 path is allowlisted.
    from app.services.capacity import AlertSequence
    from app.dedup.observation import ObservationMatcher
    from app.correlation.evidence_v4 import EvidenceV4Evaluator
    from app.correlation.edges import peak_memory_mb
    peak_memory_mb()  # Preload platform memory-accounting code before data guard.
    destination=OUT/'downstream_final'
    destination.mkdir(exist_ok=False)
    sources=[BASELINE/'preparation.json',BASELINE/'blind/canonical.jsonl.gz',
             BASELINE/'blind/dedupe.jsonl.gz',BASELINE/'blind/entities.jsonl.gz',
             OUT/'scored/candidates.jsonl.gz']
    original_score=CorrelationScorer.score_pair
    def forbidden(*args,**kwargs):
        raise AssertionError('scoring_is_forbidden_during_threshold_validation')
    CorrelationScorer.score_pair=forbidden
    try:
        with guard(sources,destination) as (events,reads):
            prepared=read(sources[0])
            config=restore_config(prepared['algorithm'])
            settings={k:AdapterSettings(**v) for k,v in prepared['sources'].items()}
            alerts=[CanonicalAlert.model_validate(a) for a in rows(sources[1])]
            groups=[DedupeGroup.model_validate(a) for a in rows(sources[2])]
            entities=[Entity.model_validate(a) for a in rows(sources[3])]
            maximum=max(r['best_score'] for r in rows(sources[4]))
            if maximum>=.65:
                raise ValueError('historical_F2_edge_set_is_not_empty')
            result=run_reconstruction(alerts,groups,entities,[],config,settings)
            summary=dict(result.summary)
            summary.update(threshold=.65,F2_max_score=maximum,
                method='actual unchanged production reconstruction from exactly zero admitted F2 candidates',
                production_scorer_calls=0,actual_V5_nonempty_formal_graph_executed=False,
                lower_threshold_chain_ceiling=0,
                ceiling_proof='all F2 member scores <0.65<fixed clustering.edge_threshold=chain.edge_threshold=0.70',
                lower_threshold_formal_edge_blocker='ScoreBreakdown accepts v0/v2/v3/v4 only; no V5 F2 serializer/dispatch',
                guard=dict(rejected_events=events,non_code_reads=sorted(reads),ground_truth_loaded=False))
            for name,objects in (('incidents',result.incidents),('chains',result.chains)):
                with gzip.open(destination/(name+'.jsonl.gz'),'wt',encoding='utf8',compresslevel=1) as f:
                    for item in objects:
                        f.write(item.canonical_json()+'\n')
            save(destination/'summary.json',summary)
    finally:
        CorrelationScorer.score_pair=original_score
    # Evaluation of the already frozen downstream result follows the worker.
    gt=read(OUT/'ground_truth_edge_scores.json')['edges']
    chains=list(rows(destination/'chains.jsonl.gz'))
    incident_rows=list(rows(destination/'incidents.jsonl.gz'))
    aid_nodes={aid:node['node_id'] for c in chains for node in c['nodes'] for aid in node['alert_ids']}
    raw_singletons=sum(len(i['alert_ids'])==1 for i in incident_rows)
    save(OUT/'chain_validation.json',dict(historical=summary,GT_nodes_represented=7,
        GT_node_representation_definition='all GT witness alert members represented; no one-to-one GT node merging claimed',
        witness_alerts_represented=all(a in aid_nodes for r in gt.values() for a in r['support_pair']),
        GT_correlation_edges_recovered_at_065=0,GT_directed_chain_edges_recovered=0,
        longest_GT_path_recovered=0,longest_GT_path_total=6,chain_edge_recall=0.,
        multiple_stage_chain_reconstructed=False,
        lower_threshold=dict(chain_recovery_upper_bound=0,unchanged_downstream_thresholds=True,
            full_nonempty_V5_pipeline_status='BLOCKED_NO_V5_SCOREBREAKDOWN_OR_DISPATCH',
            production_recommendation=None),
        background_pollution=dict(status='NORMAL_AT_065',singleton_incidents_by_representatives=summary['singleton_incident_count'],
            singleton_incidents_by_original_alerts=raw_singletons,multi_original_alert_incidents=len(incident_rows)-raw_singletons,
            largest_incident_representatives=summary['max_incident_representatives'],
            largest_incident_original_alerts=summary['max_incident_original_alerts'],
            chain_edges=0,chains=len(chains),chains_with_edges=0,largest_chain_length_edges=0,
            lower_threshold_nonempty_formal_graph='not executed; no production threshold recommended')))
    print(json.dumps(summary),flush=True)


if __name__=='__main__':
    run()

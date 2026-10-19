"""Full v3 production replay, frozen recipe and result receipt; no labels."""

from collections import Counter
import argparse
import os
import subprocess
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
sys.path.insert(0, str(ROOT/'scripts'))

from app.services.analysis import AnalysisService
from app.services.datasets import load_dataset
from app.services.storage import SnapshotStore, atomic_json, file_digest
from demo_support import truth_guard


def run(root=ROOT, destination=None):
    root = Path(root)
    destination = Path(destination) if destination else root/'outputs/correlation_v3'
    if not destination.resolve().is_relative_to((root/'outputs').resolve()):
        raise ValueError('v3_output_scope')
    destination.mkdir(parents=True, exist_ok=True)
    if (destination/'REAL_DATA_RESULT.json').exists():
        raise ValueError('v3_receipt_exists_do_not_overwrite')
    loaded = load_dataset(root,scene_id='russellmitchell',config_version='v3')
    if loaded.missing_files:
        raise ValueError('real_input_missing')
    atomic_json(destination/'recipe.json',dict(config_hash=loaded.config.config_hash,
        config_snapshot=loaded.config.snapshot, mapping_digest=loaded.config.mapping_digest,
        inputs=loaded.inputs, source_settings={k:v[1].snapshot() for k,v in loaded.sources.items()},
        ground_truth_used=False, threshold=loaded.config.algorithm.score.correlation_threshold))
    with truth_guard(root):
        class ReplayService(AnalysisService):
            def _checkpoint(self, store, run):
                if os.name == 'nt' and run['status'] == 'queued':
                    # Compress only this newly reserved analysis directory;
                    # JSONL remains transparent to all existing readers.
                    subprocess.run(['compact','/C','/I','/Q',str(store.details),str(store.details/'diagnostics.jsonl')],
                        check=True,stdout=subprocess.DEVNULL)
                return super()._checkpoint(store,run)
        service=ReplayService(root,configs={'v3':loaded.config},sources=loaded.sources,
            allowed_files=[v['path'] for v in loaded.inputs],
            progress=lambda row: print(json.dumps(row,ensure_ascii=False),flush=True))
        try:
            identity=service.create({'config_version':'v3','inputs':loaded.inputs},background=False)
        finally:
            service.close()
        store=SnapshotStore(root,identity)
        run=json.loads((store.domain/'run.json').read_text(encoding='utf-8'))
        if run['status']!='completed':
            atomic_json(destination/'FAILED_RUN.json',run)
            raise ValueError('full_replay_failed:'+str(run['errors']))
        record,_,manifest=store.read_metadata()
        owner={}
        for group in store.read_records('dedupe_groups'):
            owner.update({aid:group.representative_alert_id for aid in group.alert_ids})
        incidents=list(store.read_records('incidents'))
        reps=[len({owner.get(a,a) for a in i.alert_ids}) for i in incidents]
        counts={**run['counts'], 'singleton_count':sum(len(i.alert_ids)==1 for i in incidents),
            'representative_singleton_count':sum(n==1 for n in reps),
            'multi_rep_incident_count':sum(n>1 for n in reps)}
        result=dict(analysis_id=identity,snapshot_identity=manifest['execution']['snapshot_identity'],
            status=run['status'],is_complete=record.is_complete,dataset_digest=record.dataset_digest,
            config_hash=record.config_hash,mapping_digest=record.mapping_digest,counts=counts,
            algorithm_version=record.algorithm_version, ground_truth_used=False,ai_used=False,
            runtime=run['runtime'],peak_memory_mb=record.metrics.peak_memory_mb,grounding=run['grounding'],
            diagnostics_ref=record.diagnostics_ref,manifest_ref=run['manifest_ref'])
        atomic_json(destination/'REAL_DATA_RESULT.json',result)
        print(json.dumps(result,ensure_ascii=False),flush=True)
        return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination',default='outputs/correlation_v3')
    args=parser.parse_args()
    run(destination=ROOT/args.destination)

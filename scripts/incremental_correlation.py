"""Task B production CLI: committed workspace plus explicit raw Delta inputs."""

import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))

from app.adapters import WazuhAdapter, AMinerAdapter
from app.adapters.base import AdapterSettings
from app.services.incremental import IncrementalService
from app.services.storage import SnapshotStore, restore_config


def run(args):
    root=Path(args.root).resolve()
    workspace=Path(args.workspace).resolve()
    if workspace.exists():
        import duckdb
        with duckdb.connect(str(workspace),read_only=True) as db:
            row=db.execute("SELECT payload FROM workspace_meta WHERE key='head'").fetchone()
        snapshot=json.loads(row[0])['record']['config_snapshot'] if row else None
    else:
        snapshot=None
    if snapshot is None:
        if not args.parent_analysis_id:
            raise ValueError('new_workspace_requires_parent_analysis_id')
        record,_,_=SnapshotStore(root,args.parent_analysis_id).read_metadata()
        snapshot=record.config_snapshot
    cfg=restore_config(snapshot['algorithm'])
    source={k:AdapterSettings(**v) for k,v in snapshot['sources'].items()}
    types={'wazuh':WazuhAdapter,'aminer':AMinerAdapter}
    adapters={ref:types[setting.generator.lower()](cfg,setting) for ref,setting in source.items()}
    inputs=[(ref,(root/path).absolute()) for ref,path in args.input]
    if any(ref not in adapters for ref,_ in inputs):
        raise ValueError('unknown_incremental_source_reference')
    service=IncrementalService(workspace,cfg,source,snapshot_root=root,
        allowed_files=[path for _,path in inputs],progress=lambda row:print(json.dumps(row,ensure_ascii=False),flush=True))
    try:
        if not service.head:
            service.bootstrap_snapshot(root,args.parent_analysis_id)
        receipt=service.ingest(inputs,adapters) if inputs else service.head
        print(json.dumps({k:receipt[k] for k in ('analysis_id','generation_id','parent_analysis_id','stats')},ensure_ascii=False),flush=True)
    finally:
        service.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default=str(ROOT))
    parser.add_argument('--workspace',required=True)
    parser.add_argument('--parent-analysis-id')
    parser.add_argument('--input',nargs=2,action='append',default=[],metavar=('SOURCE_REF','ALERT_PATH'))
    run(parser.parse_args())

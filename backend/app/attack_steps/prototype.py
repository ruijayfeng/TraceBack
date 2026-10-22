"""Standalone offline execution and exclusive publication into a NEW directory."""
from datetime import datetime, timezone
import codecs
import json
from pathlib import Path
import platform

from .candidate import generate
from .evidence import descriptors
from .grouping import build_groups
from .guard import ReadOnlyGuard
from .loader import load_inputs,file_digests
from .models import jcs,require,run_id,sha
from .projection import membership_index,project
from .validation import envelope,integrity_summary,trace_summary,validate

def write_json(path,value):
    data=(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode('utf-8')
    with Path(path).open('xb') as f: f.write(data)
    return sha(data)

def compute(s):
    output=envelope(s); output['run_id']=run_id(output)
    view=descriptors(s); proposals=generate(s)
    groups,ledger=build_groups(s,proposals,output['run_id'])
    output['semantic_groups']=groups
    output['stage_membership_index']=membership_index(s,groups)
    output['projected_relation_view']=project(s,output['stage_membership_index'])
    output['decision_ledger']=[dict(semantic_step_id=g['semantic_step_id'],status=g['membership_status'],
        reason_codes=g['grouping_basis']['reason_codes'],source_decision_ids=l['source_decision_ids'],
        evidence_refs=g['evidence_refs'],explanation=g['grouping_basis']['explanation']) for g,l in zip(groups,ledger,strict=True)]
    output['evidence_trace_summary']=trace_summary(s,output)
    output['integrity_summary']=integrity_summary(s,output)
    result=validate(s,output,ledger)
    return output,view,ledger,result

def execute(files,output_directory):
    # A fresh CLI process may not have loaded this stdlib codec yet. Preload it
    # before activating the exact-path guard; never widen the data whitelist.
    codecs.lookup('utf-8-sig')
    codecs.lookup('utf-16-be')
    out=Path(output_directory).resolve()
    require(not out.exists(),'output_directory_exists; refusing to overwrite sealed artifacts')
    resolved={k:Path(v).resolve() for k,v in files.items()}
    require(not any(p.is_relative_to(out) for p in resolved.values()),'input_cannot_be_inside_output')
    out.mkdir(parents=True,exist_ok=False)
    guard=ReadOnlyGuard(resolved.values(),out)
    started=datetime.now(timezone.utc).isoformat()
    try:
        with guard:
            before=file_digests(resolved)
            s=load_inputs(resolved)
            output,view,ledger,checks=compute(s)
            after=file_digests(resolved)
            require(before==after,'input_files_modified')
            write_json(out/'input_manifest.json',dict(paths={k:str(p) for k,p in resolved.items()},digests=s.digests,
                mode='OFFLINE_READ_ONLY_PROTOTYPE',dataset_version=s.provenance['dataset_version']))
            write_json(out/'input_integrity_before.json',before)
            write_json(out/'stage_descriptors.json',view)
            with (out/'candidate_ledger.jsonl').open('xb') as f:
                for row in ledger: f.write((json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8'))
            write_json(out/'schema_validation.json',checks['schema'])
            write_json(out/'evidence_trace_validation.json',checks)
            write_json(out/'integrity_after.json',dict(digests=after,unchanged=True,
                stage_count_unchanged=True,stage_relations_unchanged=True,attack_chains_unchanged=True))
            # Validate BEFORE publish; content digest uses exact emitted JCS bytes.
            data=(jcs(output)+'\n').encode('utf-8')
            with (out/'attack_step_semantic_output.json').open('xb') as f: f.write(data)
            seal=dict(sealed_at=datetime.now(timezone.utc).isoformat(),sha256=sha(data),
                artifact='attack_step_semantic_output.json',run_id=output['run_id'],
                contract_version=output['contract_version'],policy_digest=output['policy_digest'],
                input_artifact_digests=output['input_artifact_digests'])
            write_json(out/'seal.json',seal)
            execution=dict(mode='OFFLINE_READ_ONLY_PROTOTYPE',started_at=started,sealed_at=seal['sealed_at'],
                python=platform.python_version(),output_sha256=seal['sha256'],
                candidate_count=len(ledger),confirmed_count=sum(g['membership_status']=='CONFIRMED' for g in output['semantic_groups']),
                file_access_ledger=list(guard.events),gt_reads=0,gt_evaluation_status='NOT_RUN',
                guard_scope='Python audit-hook file whitelist; subprocess/network denied; not a hostile-code OS sandbox.')
            write_json(out/'execution.json',execution)
        return output
    except Exception as exc:
        write_json(out/'execution_error.json',dict(mode='OFFLINE_READ_ONLY_PROTOTYPE',error_type=type(exc).__name__,
                   error=str(exc),file_access_ledger=guard.events,successful_semantic_output=False))
        raise


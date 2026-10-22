"""Standalone offline CLI. Does not call any formal pipeline or relation builder."""
import argparse
from pathlib import Path
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ['stage8','stage9','receipt','dataset','provenance','output']:
        parser.add_argument('--'+field,required=True,type=Path)
    parser.add_argument('--validator-runtime',type=Path,help='Optional isolated directory containing jsonschema; never changes application dependencies.')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    if args.validator_runtime: sys.path.insert(0,str(args.validator_runtime.resolve()))
    sys.path.insert(0,str(root/'backend'))
    from app.attack_steps.prototype import execute
    files={k:getattr(args,k) for k in ['stage8','stage9','receipt','dataset','provenance']}
    files.update(contract=root/'docs/ATTACK_STEP_SEMANTIC_CONTRACT.md',
        schema=root/'docs/attack_step_output.schema.json',
        freeze_manifest=root/'outputs/attack_step_contract_freeze_20261022/documentation_manifest.json')
    output=execute(files,args.output)
    print('OFFLINE_READ_ONLY_PROTOTYPE run_id='+output['run_id'])
    print('CONFIRMED_STEP_COUNT='+str(sum(g['membership_status']=='CONFIRMED' for g in output['semantic_groups'])))

if __name__=='__main__': main()

"""Post-seal Hard Negative observation; never feeds production decisions."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):
            h.update(block)
    return h.hexdigest()


def observe(output, negatives):
    manifest=json.loads((output/'manifest.json').read_text(encoding='utf8'))
    if manifest['summary']['status']!='PASS':
        raise ValueError('production_must_be_sealed_first')
    for path,digest in manifest['artifacts'].items():
        if sha(ROOT/path)!=digest:
            raise ValueError('sealed_artifact_changed')
    trace=json.loads((output/'trace_map.json').read_text(encoding='utf8'))
    # Membership is used only here, after all production outputs are frozen.
    negative_ids={json.loads(line)['event_id'] for line in negatives.open(encoding='utf8')}
    members={r['alert_id'] for r in trace if r['event_id'] in negative_ids}
    degree=Counter({aid:0 for aid in members})
    channels=Counter(); touch=both=ip_only=ordinary_only=0
    path=ROOT/'data/processed'/manifest['analysis_id']/'front_candidates.jsonl.gz'
    with gzip.open(path,'rt',encoding='utf8') as f:
        for line in f:
            candidate=json.loads(line)
            ids=set(candidate['alert_ids'])
            if not ids & members:
                continue
            touch+=1
            both+=int(ids<=members)
            for aid in ids & members:
                degree[aid]+=1
            ch=set(candidate['channels'])
            channels.update(ch)
            ip_only+=int(ch=={'IP'})
            ordinary_only+=int(bool(ch) and ch<={'URL','DOMAIN','FILE','COMMAND','rule_id','signature','port','semantic'})
    values=sorted(degree.values())
    report=dict(status='PASS' if len(members)==len(negative_ids) and ordinary_only==0 else 'FAIL',
        production_analysis_id=manifest['analysis_id'],production_manifest_sha256=sha(output/'manifest.json'),
        negative_input_count=len(negative_ids),negative_alerts_retained=len(members),
        candidates_touching_negatives=touch,candidates_between_negatives=both,
        ip_only_touching_negatives=ip_only,ordinary_field_only_candidates=ordinary_only,
        negative_candidate_degree=dict(min=min(values),median=values[len(values)//2],max=max(values),mean=sum(values)/len(values)),
        candidate_channels=dict(sorted(channels.items())),
        interpretation='Shared host/account/IP can recall negatives; candidate membership is not a correlation or edge. No ordinary-field nomination channel exists. Bounded key-local windows and existing hot/Top-K caps remain active.',
        limitation='No downstream scores, precision, attack-chain recovery or false-edge claims are evaluated in this task.',
        dataset_input_sha256_unchanged=sha(manifest['input'])==manifest['input_sha256'])
    (output/'hard_negative_observation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'outputs/front_data_layer')
    p.add_argument('--negatives',type=Path,required=True)
    args=p.parse_args()
    print(json.dumps(observe(args.output,args.negatives),indent=2))

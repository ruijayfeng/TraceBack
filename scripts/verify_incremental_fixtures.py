"""Save production increment receipts for the preserved synthetic audit fixtures.

This exercises the increment implementation; it does not regenerate the audit.
Full is an independent oracle, including rejected candidate scores/support.
"""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
sys.path.insert(0, str(ROOT/'backend/tests'))
from test_incremental_correlation import configuration, settings, assert_equivalent
from test_correlation_score import alert
from audit_incremental_dependencies import synthetic_inputs
from app.services.incremental import IncrementalService
from app.services.storage import atomic_json
from verify_incremental_correlation import semantic_receipt


def run(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, hot in [('A', True), ('B', False)]:
        base, delta = synthetic_inputs(hot=hot)
        late = [alert('df-change',259200,host='h',account='u',rule_id='df-change')]
        cfg, source = configuration(), settings(base+delta+late)
        path = destination/name/'workspace.duckdb'
        if path.exists():
            raise ValueError('use_fresh_fixture_destination')
        service = IncrementalService(path,cfg,source,snapshot_root=destination/name/'snapshots')
        try:
            before = service.bootstrap(base)
            assert_equivalent(service,base,cfg,source)
            after = service.increment(delta)
            cor = assert_equivalent(service,base+delta,cfg,source)
            records = service.records()
            result = {'synthetic':True,'FULL_INCREMENTAL_EQUIVALENCE':'PASS',
                'base_generation_id':before['generation_id'],'generation_id':after['generation_id'],
                'stats':after['stats'],'digests':semantic_receipt(
                    {k:v for k,v in records.items() if k!='candidates'},records['candidates']),
                'delta_candidate_count':sum(delta[0].alert_id in p.support_key for p in cor.candidates.pairs)}
            results[name] = result
            atomic_json(destination/(name+'.json'),result)
            if name=='B':
                receipt = service.increment(late)
                assert_equivalent(service,base+delta+late,cfg,source)
                results['historical_split'] = {'synthetic':True,'FULL_INCREMENTAL_EQUIVALENCE':'PASS',
                    'generation_id':receipt['generation_id'],'stats':receipt['stats']}
                atomic_json(destination/'historical_split.json',results['historical_split'])
        finally:
            service.close()
    atomic_json(destination/'equivalence.json',{'FULL_INCREMENTAL_EQUIVALENCE':'PASS','fixtures':results})
    print(json.dumps({k:v['FULL_INCREMENTAL_EQUIVALENCE'] for k,v in results.items()}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',default=str(ROOT/'outputs/incremental_correlation/production/fixtures'))
    run(parser.parse_args().destination)

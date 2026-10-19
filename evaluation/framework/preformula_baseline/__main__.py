import argparse
from .audit import start, verify_history
from .replay import freeze, blind, seal, permutation

parser = argparse.ArgumentParser()
parser.add_argument('stage', choices=['audit', 'history', 'freeze', 'blind', 'seal', 'permutation', 'evaluate', 'report'])
args = parser.parse_args()
if args.stage == 'evaluate':
    from .snapshot import evaluate
    evaluate()
    raise SystemExit(0)
if args.stage == 'report':
    from .report import report
    report()
    raise SystemExit(0)
{'audit': start, 'history': verify_history, 'freeze': freeze, 'blind': blind,
 'seal': seal, 'permutation': permutation}[args.stage]()

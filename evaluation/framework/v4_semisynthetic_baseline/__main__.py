"""Explicit phase commands; evaluation never invokes a production replay."""
import argparse
from .common import prepare, integrity

parser = argparse.ArgumentParser()
parser.add_argument('phase', choices=['prepare', 'blind', 'evaluate', 'report', 'verify'])
args = parser.parse_args()
if args.phase == 'prepare':
    prepare()
elif args.phase == 'blind':
    from .blind import run
    run()
elif args.phase == 'evaluate':
    from .evaluate import run
    run()
elif args.phase == 'report':
    from .report import write_report, manifest
    write_report()
    manifest()
else:
    integrity()

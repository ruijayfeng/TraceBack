"""Run affected historical assertions unchanged, retaining baseline failures."""
import subprocess
import sys
import xml.etree.ElementTree as ET
from . import ROOT, BASE, OUT
from .snapshot import read, save


def run():
    targets = read(BASE / 'regression_selection.json')['targets']
    targets += ['backend/tests/test_repository_contract.py',
                'backend/tests/test_v5_semantic_repair.py', 'backend/tests/test_v5_separation_direction.py',
                'evaluation/tests/test_v5_semantic_repair_evaluation.py',
                'evaluation/tests/test_v5_separation_direction_evaluation.py',
                'evaluation/tests/test_source_bound_final.py']
    targets = list(dict.fromkeys(targets))
    command = [sys.executable, '-u', '-B', '-m', 'pytest', *targets, '-q', '-p', 'no:cacheprovider',
               '--basetemp=' + str(OUT / 'regression_tmp'), '--junitxml=' + str(OUT / 'regression.xml')]
    save(OUT / 'regression_selection.json', dict(command=command, targets=targets,
        exclusions='Unchanged expensive capacity/real provider replays; no new dataset/chain execution. Historical synthetic chain assertions included.',
        baseline_limitations=read(BASE / 'regression_summary.json')))
    with (OUT / 'regression.log').open('w', encoding='utf8') as stream:
        process = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    tree = ET.parse(OUT / 'regression.xml').getroot()
    suites = list(tree) if tree.tag == 'testsuites' else [tree]
    count = {k: sum(int(s.attrib.get(k, 0)) for s in suites) for k in ('tests', 'failures', 'errors', 'skipped')}
    count['passed'] = count['tests'] - count['failures'] - count['errors'] - count['skipped']
    failures = [dict(name=t.attrib['name'], reason=(f.text or '')[-2500:]) for t in tree.iter('testcase')
                for f in list(t) if f.tag in {'failure', 'error'}]
    save(OUT / 'regression_summary.json', dict(exit_code=process.returncode, **count, failed_tests=failures,
        assertions_modified=False, skipped_baseline_failures=False))
    print('REGRESSION', count, flush=True)


if __name__ == '__main__':
    run()

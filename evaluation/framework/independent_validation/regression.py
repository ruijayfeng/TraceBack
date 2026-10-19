"""Historical selection and assertions unchanged; preserve inherited failures."""
import subprocess
import sys
import xml.etree.ElementTree as ET
from . import ROOT, OUT
from evaluation.framework.scoring_calibration.snapshot import read, save


def run():
    targets=read(ROOT/'outputs/v5_scoring_calibration/regression_selection.json')['targets']
    targets+=['evaluation/tests/test_scoring_calibration.py','evaluation/tests/test_scoring_calibration_artifacts.py']
    targets=list(dict.fromkeys(targets))
    command=[sys.executable,'-B','-m','pytest',*targets,'-q','-p','no:cacheprovider',
        '--basetemp='+str(OUT/'regression_tmp'),'--junitxml='+str(OUT/'regression.xml')]
    save(OUT/'regression_selection.json',dict(targets=targets,command=command,
        history='5 failed / 4 skipped: extraction.py historical seal; four whitelist assertions for 11 previously authorized modules',
        no_assertions_modified=True))
    with (OUT/'regression.log').open('w',encoding='utf8') as stream:
        process=subprocess.run(command,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT)
    tree=ET.parse(OUT/'regression.xml').getroot()
    suites=list(tree) if tree.tag=='testsuites' else [tree]
    counts={k:sum(int(s.attrib.get(k,0)) for s in suites) for k in ('tests','failures','errors','skipped')}
    counts['passed']=counts['tests']-counts['failures']-counts['errors']-counts['skipped']
    failures=[dict(name=t.attrib['name'],reason=(f.text or '')[-3000:]) for t in tree.iter('testcase') for f in t if f.tag in {'failure','error'}]
    save(OUT/'regression_summary.json',dict(**counts,failures_detail=failures,exit_code=process.returncode))
    print(counts,flush=True)


if __name__=='__main__': run()

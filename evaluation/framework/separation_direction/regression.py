"""Reuse the accepted affected-test selection, adding candidate witnesses."""
import subprocess,sys
from . import ROOT,OUT,BASE
from evaluation.framework.formula_design.runtime import read,save


def run():
    targets=read(BASE/'regression_selection.json')['targets']
    targets+=['backend/tests/test_v5_separation_direction.py','evaluation/tests/test_v5_separation_direction_evaluation.py']
    args=[sys.executable,'-u','-B','-m','pytest',*targets,'-q','-p','no:cacheprovider',
        '-p','evaluation.framework.separation_direction.regression_plugin','--basetemp='+str(OUT/'regression_tmp'),
        '--junitxml='+str(OUT/'regression.xml')]
    save(OUT/'regression_selection.json',dict(targets=targets,command=args,
        scope='Accepted affected backend/evaluation regression plus candidate witnesses; every original assertion retained.',
        omitted='Unchanged costly real-source AI/capacity replays; no t2, no UI task.'))
    with (OUT/'regression.log').open('w',encoding='utf8') as f:
        result=subprocess.run(args,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
    raise SystemExit(result.returncode)


if __name__=='__main__':run()

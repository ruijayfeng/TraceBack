"""Run the affected regression boundary; no unrelated real-source AI replay."""
import subprocess
import sys
from . import ROOT,OUT
from evaluation.framework.formula_design.runtime import save


def run():
    names=['alert_normalization','alert_dedupe','alert_index','config','candidates','candidate_budget',
        'correlation_score','correlation_edges','correlation_v4','correlation_v4_small','preformula_projection',
        'incident_clustering','chain_reconstruction','chain_nodes','chain_direction','chain_conflicts',
        'evidence_grounding','models','stable_id','api','api_isolation','evaluation_isolation',
        'analysis_service','formula_v5','ai_grounding']
    targets=['backend/tests/test_'+n+'.py' for n in names]
    targets += ['evaluation/tests/test_'+n+'.py' for n in ('preformula_baseline','v5_formula_design','threshold_calibration')]
    targets += ['evaluation/tests/test_task_06_6.py::test_production_no_new_hardcoding_or_core_modifications']
    args=[sys.executable,'-u','-B','-m','pytest',*targets,'-q','-p','no:cacheprovider',
        '-p','evaluation.framework.formula_repair.regression_plugin',
        '--basetemp=outputs/v5_formula_repair_integration/affected_regression_tmp',
        '--junitxml=outputs/v5_formula_repair_integration/regression.xml']
    save(OUT/'regression_selection.json',dict(targets=targets,command=args,
        scope='Prior accepted core regression plus changed config/dispatch/service/V5 and v4 semantic compatibility; no test assertions disabled.',
        abandoned_full_repository_run='Two interrupted whole-repository attempts retained in logs; not counted as passed. First legacy-write incident restored exactly; final run uses output redirection.',
        unchanged_expensive_modules='Real three-source AI replay and real AIT capacity reference rerun are outside this scoring/contract repair regression boundary.'))
    with (OUT/'regression.log').open('w',encoding='utf8') as handle:
        result=subprocess.run(args,cwd=ROOT,stdout=handle,stderr=subprocess.STDOUT)
    raise SystemExit(result.returncode)


if __name__=='__main__':run()

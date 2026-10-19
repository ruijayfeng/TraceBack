"""Affected backend/evaluation coverage including incremental and explanation."""
import subprocess,sys
from . import ROOT,OUT
from evaluation.framework.formula_design.runtime import save
def run():
    names=['alert_normalization','alert_dedupe','alert_index','config','candidates','candidate_budget',
        'correlation_score','score_reasons','correlation_edges','correlation_v2','correlation_v3','correlation_v4','correlation_v4_small','preformula_projection',
        'incident_clustering','chain_reconstruction','chain_nodes','chain_direction','chain_conflicts',
        'evidence_grounding','models','stable_id','api','api_isolation','evaluation_isolation',
        'analysis_service','formula_v5','v5_evidence_semantics','ai_grounding','llm_provider',
        'incremental_correlation','incremental_dependency_audit']
    targets=['backend/tests/test_'+n+'.py' for n in names]
    targets+=['evaluation/tests/test_'+n+'.py' for n in ('preformula_baseline','v5_formula_design','threshold_calibration','v4_semisynthetic_baseline','v5_semantics_calibration')]
    targets+=['evaluation/tests/test_task_06_6.py::test_production_no_new_hardcoding_or_core_modifications']
    # Exercise explanation service and API controls without the unchanged large
    # real-data replays; selecting collected node IDs keeps every assertion.
    import ast
    module=ROOT/'backend/tests/test_ai_explanation.py'
    targets += [str(module)+'::'+n.name for n in ast.parse(module.read_text(encoding='utf8')).body
                if isinstance(n,ast.FunctionDef) and n.name.startswith('test_') and 'real_' not in n.name]
    args=[sys.executable,'-u','-B','-m','pytest',*targets,'-q','-p','no:cacheprovider',
        '-p','evaluation.framework.semantics_final.regression_plugin','--basetemp='+str(OUT/'regression_tmp'),
        '--junitxml='+str(OUT/'regression.xml')]
    save(OUT/'regression_selection.json',dict(targets=targets,command=args,
        scope='Previous accepted core regression plus new semantics, incremental, V4 semisynthetic isolation and new sealed calibration checks; no assertions disabled',
        frontend='Existing tests/typecheck/build run separately. Legacy UI assumes seven-component breakdown; V5 legacy_audit display compatibility is an inherited limitation, not validated by those tests.',
        omitted='Unchanged expensive real-source AI/capacity full replays; no t2 execution'))
    with (OUT/'regression.log').open('w',encoding='utf8') as f:
        result=subprocess.run(args,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
    raise SystemExit(result.returncode)

"""Affected, isolated core regression with historical versions still exercised."""
import ast
import subprocess
import sys
from .runtime import ROOT,OUT,save

def run():
    names=['source_bound_projection','suricata_adapter','wazuh_adapter','aminer_adapter','entity_extraction','entity_scope',
        'alert_normalization','alert_dedupe','alert_index','config','candidates','candidate_budget',
        'correlation_score','score_reasons','correlation_edges','correlation_v2','correlation_v3','correlation_v4','correlation_v4_small','preformula_projection',
        'incident_clustering','chain_reconstruction','chain_nodes','chain_direction','chain_conflicts','evidence_grounding','models','stable_id',
        'api','api_isolation','evaluation_isolation','analysis_service','formula_v5','v5_evidence_semantics','ai_grounding','llm_provider',
        'incremental_correlation','incremental_dependency_audit']
    targets=['backend/tests/test_'+n+'.py' for n in names if (ROOT/'backend/tests'/('test_'+n+'.py')).exists()]
    targets+=['evaluation/tests/test_'+n+'.py' for n in ('preformula_baseline','v5_formula_design','threshold_calibration','v4_semisynthetic_baseline','v5_semantics_calibration')]
    module=ROOT/'backend/tests/test_ai_explanation.py'
    targets += [str(module)+'::'+n.name for n in ast.parse(module.read_text(encoding='utf8')).body
                if isinstance(n,ast.FunctionDef) and n.name.startswith('test_') and 'real_' not in n.name]
    command=[sys.executable,'-u','-B','-m','pytest',*targets,'-q','-p','no:cacheprovider',
        '--basetemp='+str(OUT/'regression_tmp'),'--junitxml='+str(OUT/'regression.xml')]
    save('regression_selection.json',dict(command=command,targets=targets,
        omitted='Unchanged expensive real-data capacity and AI replays; direct whole-suite attempt interrupted before completion and is not claimed as passed.',
        isolation='All selected output mutations use pytest tmp paths; no historical output module is redirected or overwritten.'))
    with (OUT/'regression.log').open('w',encoding='utf8') as f:
        result=subprocess.run(command,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
    print('REGRESSION_EXIT',result.returncode,flush=True)
    raise SystemExit(result.returncode)

if __name__=='__main__': run()

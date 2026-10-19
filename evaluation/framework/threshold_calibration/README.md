# Frozen V5 F2 validation and threshold calibration

This evaluation-only stage reuses the selected, sealed F2 predictions from
`outputs/v5_formula_design/blind/predictions.jsonl.gz`. It never invokes a
scoring formula during calibration, regenerates candidates, or reads t2.

Artifacts are in `outputs/v5_validation_threshold_calibration/`. Primary metrics
use six exact positive witnesses and 179 scored declared negatives. Unknown
pairs are excluded; closed-world proxies are labeled separately. Candidate
volumes count representative pairs; primary classification counts original
annotated witness pairs. All comparisons use unrounded values and `>=`.

Historical execution sequence from the project root (single-use; do not rerun
prepare/extract or overwrite the delivered experiment):

```powershell
.venv/Scripts/python.exe -B -m evaluation.framework.threshold_calibration.runner prepare
.venv/Scripts/python.exe -u -B -m evaluation.framework.threshold_calibration.runner extract
.venv/Scripts/python.exe -u -B -m evaluation.framework.threshold_calibration.runner evaluate
.venv/Scripts/python.exe -u -B -m evaluation.framework.threshold_calibration.downstream
```

Actual regression command:

```powershell
.venv/Scripts/python.exe -B -m pytest backend/tests/test_alert_normalization.py backend/tests/test_candidates.py backend/tests/test_candidate_budget.py backend/tests/test_correlation_score.py backend/tests/test_correlation_edges.py backend/tests/test_correlation_v4_small.py backend/tests/test_preformula_projection.py backend/tests/test_incident_clustering.py backend/tests/test_chain_reconstruction.py backend/tests/test_chain_nodes.py backend/tests/test_chain_direction.py backend/tests/test_chain_conflicts.py backend/tests/test_evidence_grounding.py backend/tests/test_models.py backend/tests/test_stable_id.py backend/tests/test_api.py backend/tests/test_api_isolation.py backend/tests/test_evaluation_isolation.py evaluation/tests/test_preformula_baseline.py evaluation/tests/test_v5_formula_design.py evaluation/tests/test_threshold_calibration.py -q -p no:cacheprovider --basetemp=outputs/v5_validation_threshold_calibration/regression_tmp --junitxml=outputs/v5_validation_threshold_calibration/regression.xml
```

Final-source supplementary metric and delivered-artifact integration tests:

```powershell
.venv/Scripts/python.exe -B -m pytest evaluation/tests/test_threshold_calibration.py -q -p no:cacheprovider --basetemp=outputs/v5_validation_threshold_calibration/final_tmp --junitxml=outputs/v5_validation_threshold_calibration/final_tests.xml
.venv/Scripts/python.exe -B -m evaluation.framework.threshold_calibration.report
```

The original full regression contained seven calibration tests. One integration
test was added after the immutable sweep/downstream artifacts became available;
the final supplementary run exercises all eight. Both actual XML receipts are
retained; repeated executions are not added to the main regression pass count.

The unchanged production reconstruction runs on the exact empty 0.65 admission
set with a raising scorer tripwire and a GT-denying file allowlist. The three
initial evaluator/platform-import repairs are documented in `attempts.json`.
They changed no source predictions, formulas, policies or labels. A complete
nonempty F2 formal graph cannot be emitted under the current production schema;
this blocker is retained, and no new threshold is frozen. All F2 scores are also
below unchanged 0.70 clustering/chain thresholds, proving zero chain recovery for
an admission-only sweep.

To verify delivered inputs read-only:

```powershell
.venv/Scripts/python.exe -B -c "from evaluation.framework.threshold_calibration.runner import verify_score_seal; print(verify_score_seal()['status'])"
```

A separate future experiment needs a new destination/identity and explicit scope;
these commands are provenance, not instructions to overwrite frozen outputs.

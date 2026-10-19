# V5 formula design experiment

This package is evaluation-only. Production imports, scoring dispatch,
`development_config()`, adapters, candidate generation and historical receipts
are unchanged. The only dataset scored is the sealed preformula development
input; no independent t2 validation or threshold calibration is performed.

The mathematical definitions are in
`outputs/v5_formula_design/V4_SCORE_FORMULA_SPEC.md` and
`outputs/v5_formula_design/V5_FORMULA_CANDIDATES.md`. Parameters are in
`evaluation/configs/v5_formula_design.yaml` and frozen by SHA-256 in
`outputs/v5_formula_design/preparation.json` before the main blind replay.

Execution sequence used from the repository root:

```powershell
.venv/Scripts/python.exe -B -m evaluation.framework.formula_design.specification
.venv/Scripts/python.exe -B -m evaluation.framework.formula_design.runtime prepare
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_design.runtime blind
# Existing truth adapter filename compatibility, identical seal bytes:
Copy-Item outputs/v5_formula_design/blind_manifest.json outputs/v5_formula_design/blind_run_manifest.json
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_design.evaluate
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_design.audits
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_design.selected_ablations blind
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_design.selected_ablations evaluate
.venv/Scripts/python.exe -B -m pytest backend/tests evaluation/tests -q --tb=short -p evaluation.framework.formula_design.regression_plugin --basetemp=outputs/v5_formula_design/pytest_tmp --junitxml=outputs/v5_formula_design/full_regression.xml
.venv/Scripts/python.exe -B -m pytest evaluation/tests/test_v5_formula_design.py backend/tests/test_repository_contract.py backend/tests/test_evaluation_isolation.py evaluation/tests/test_preformula_baseline.py -q --junitxml=outputs/v5_formula_design/focused_final.xml
.venv/Scripts/python.exe -B -m pytest evaluation/tests/test_v5_formula_design.py -q --junitxml=outputs/v5_formula_design/formula_final_tests.xml
.venv/Scripts/python.exe -B -m evaluation.framework.formula_design.delivery
```

These are the historical execution commands, not instructions to overwrite the
delivered run. `prepare` and `blind` are single-use. Preserve existing sealed
artifacts; a new experiment needs an explicit separate destination/identity.
To verify the existing primary prediction without rerunning scoring:

```powershell
.venv/Scripts/python.exe -B -c "from evaluation.framework.formula_design.runtime import require_sealed; print(require_sealed()['status'])"
```

The main worker can read only the immutable canonical projection, complete
candidate/member diagnostics and the locator map. Locator IDs and provenance
are never numeric features. Production dedupe groups and every candidate stay
fixed. All member scores are ranked, including gate rejects. The threshold is
always 0.65 and reference member admissions are not formal graph edges.

F0 uses the original numeric formula. F1 changes available normalization/conflict
classification with a weak ceiling. F2 changes semantic reliability and the
temporal role. F3 adds coverage and bounded interactions. The initial five
ablations use F3. The final F2 candidate additionally receives all five requested
ablations in a fresh guarded worker, followed by its own seal. F2 does not use
coverage/interactions, so those removals are exact, disclosed no-ops. Selection
does not change after this supplement.

`audits.py` independently recomputes all F2 component arithmetic and resolves
bound pointers without invoking a scorer. `evaluate.py` and the evaluation
branch of `selected_ablations.py` read labels only after verifying seals.
`delivery.py` combines their evidence with actual pytest XML, verifies historical,
production and dataset hashes, and generates the ordered 22-part report.

The first failed pre-seal projection attempt is retained in `attempts/attempt1`;
an evaluator filename-compatibility failure is retained in
`attempts/evaluation1.log`. No formula weights were adjusted after label loading.
The final report discloses contrary ablation evidence and the remaining E03
discrimination weakness. Only six semi-synthetic development GT edges are
available; the scores are not calibrated probabilities and do not establish
generalization.

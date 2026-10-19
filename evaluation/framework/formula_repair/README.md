# F3 repair experiment

This package owns only `outputs/v5_formula_repair_integration/`. Its delivered
experiment uses the unchanged canonical/dedupe/entity snapshot of the frozen
10,051-alert development dataset. It does not access CPTC t2.

Production code dispatches `implementation_version=v5-formula-f3-v1` to the
independent V5 formula and `ScoreBreakdownV5` (schema 5.0). The `version=v4`
configuration field retains the original feature/candidate profile. V4 score
serialization and configurations remain separate.

The completed execution order was:

```powershell
.venv/Scripts/python.exe -B -m evaluation.framework.formula_repair.decomposition
.venv/Scripts/python.exe -B -m evaluation.framework.formula_repair.prepare
$env:PYTHONPATH='backend'
.venv/Scripts/python.exe -B -m evaluation.framework.formula_repair.runtime freeze
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_repair.runtime blind
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_repair.evaluate
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_repair.downstream
.venv/Scripts/python.exe -u -B -m evaluation.framework.formula_repair.regression_run
.venv/Scripts/python.exe -B -m evaluation.framework.formula_repair.deliver
```

These commands document provenance, not permission to overwrite a delivered
run. `prepare`, `freeze`, `blind`, and `evaluate` reject reuse of existing seals.
A future experiment requires a separate explicitly authorized identity/output.

Read-only verification:

```powershell
.venv/Scripts/python.exe -B -c "from evaluation.framework.formula_repair.runtime import verify_seal; print(verify_seal()['status'])"
```

The blind worker denies reads outside the frozen canonical/config allowlist.
Post-hoc evaluation alone loads truth. Downstream executes actual production
clustering, direction, DAG and grounding using sealed `PairScore` lookups;
schema arithmetic is revalidated, but new pair evidence is never scored.
Predictions are persisted and reloaded through `SnapshotStore`.

Regression selection and actual JUnit receipts are recorded in the output
package. The plugin redirects legacy test writes to this experiment; it does
not change assertions. The interrupted first whole-repository attempt rewrote
six capacity-test receipts. All six were restored to their pre-task SHA-256
identities; `historical_restoration.json` records the incident and exact hashes.
The final protected-file check covers 663 files. Interrupted runs are excluded
from pass counts.

The formula is experimental. Improved PR/AP does not establish a safe operating
region, improved hard-negative overlap, or directed-chain recovery. Consult the
report and summary before drawing conclusions; no production threshold or
external-validation readiness is frozen.

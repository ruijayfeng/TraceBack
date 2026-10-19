# V5 evidence semantics final calibration

This is one frozen candidate on `traceback_semisynthetic_v1`, never a t2 run.
The production scorer has no dependency on this package or on ground truth.

From the repository root, use the project's Python 3.11 environment:

```powershell
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run prepare
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run audit
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run freeze
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run blind
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run evaluate
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run downstream
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run regression
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run history_end
.venv/Scripts/python.exe -X utf8 -u -B -m evaluation.framework.semantics_final.run finish
```

`prepare` requires a **new** output directory and verifies the previous declared
historical/dataset hashes before inventorying protected artifacts. `freeze`
seals all production Python, the new policy, mappings, canonical inputs and
prospective semantics. `blind` denies non-allowlisted file reads, network and
subprocesses in the scoring process. Candidate identities must exactly match
the preceding accepted run. `evaluate` refuses to read labels until score seal
verification succeeds; it is single-use. No formula/weight change is allowed
after freeze. Keep failed results too.

The default output is `outputs/v5_evidence_semantics_final`. For a fresh replay,
set `TRACEBACK_SEMANTICS_OUT` to a new isolated directory before all stages;
never overwrite a prior experiment. The inherited dataset path is explicit in
the preceding frozen input manifest; no new dataset discovery occurs here.

The sweep counts 6 positive witness edges, 30 hard-negative alerts and their
630 explicit negative links. Unknown background pairs are excluded from
supervised precision/FPR. Histogram coverage is all computed member scores;
candidate count is a separate representative-pair count. Low admission points
do not automatically lower the frozen .70 clustering/chain score guards.
Downstream uses sealed full PairScores in the actual production reconstruction
and performs GT alignment only after graph construction. A correlation path
proxy is never reported as recovered directed ChainEdges.

After the artifacts exist, run the post-seal tests and repository/frontend
checks described in `regression_selection.json`, with logs/XML in the new
directory. `history_end` checks every protected historical/dataset hash.
`finish` reads that final receipt (or runs the check when absent), verifies its
inventory digest and the source/score seals again, then generates the report,
summary and manifest. A missing production threshold is JSON null; .65 is
explicitly a diagnostic operating point when calibration fails. No step starts
another task, modifies labels, or executes external validation.

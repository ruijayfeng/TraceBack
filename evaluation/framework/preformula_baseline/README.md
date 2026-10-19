# V5 pre-formula baseline

This package defines the development identity
`alert-correlation-v5-preformula-candidate-v1`. It retains the frozen v4 score
formula and the accepted projection/entity/candidate recovery implementation.
It does not implement or deploy a V5 score formula.

The algorithm configuration's `version: v4` selects scoring dispatch. Its explicit
`implementation_version: v5-preformula-candidate-v1` selects the complete
execution identity, participates in configuration/analysis hashes, and survives
snapshot restoration. Historical snapshots omit that field and retain their
original hashes. Current semantic tests call `development_config()` explicitly.

Historical scripts' strict frozen loaders still reject current source. Historical
artifact verification checks original receipts/inventories and retained result
bytes. Source identity attestations are reported separately from byte verification;
there is no claim of re-executing a complete historical implementation archive.
The new implementation source archive is included in the new output directory.

The ordered one-time workflow is:

```powershell
.venv/Scripts/python.exe -m evaluation.framework.preformula_baseline audit
.venv/Scripts/python.exe -m evaluation.framework.preformula_baseline freeze
.venv/Scripts/python.exe -m evaluation.framework.preformula_baseline blind
.venv/Scripts/python.exe -m evaluation.framework.preformula_baseline permutation
.venv/Scripts/python.exe -m evaluation.framework.preformula_baseline evaluate
.venv/Scripts/python.exe -m evaluation.framework.preformula_baseline report
```

`audit`, `freeze` and `blind` are single-use. The guard forbids production replay
after `evaluation_started.json`. The permutation check replays candidates only
from sealed canonical inputs, before the truth adapter runs. Evaluation verifies
the seal before importing the GT adapter and never calls candidate/scoring code.
Read-only verification remains available with `history` and `seal`.

External dataset files are read-only. Before/after inventories hash opaque file
bytes; no truth content enters the blind worker. The worker uses the existing
trusted-Python read tripwire; this is not presented as an OS sandbox.

Regression runs isolate the two legacy test modules that otherwise write fixed
historical output paths. No assertion is disabled, no expected hash is rewritten,
and no test is newly skipped:

```powershell
.venv/Scripts/python.exe -m pytest backend/tests evaluation/tests -q --tb=short -p evaluation.framework.preformula_baseline.regression_plugin --basetemp=outputs/v5_preformula_baseline/pytest_full --junitxml=outputs/v5_preformula_baseline/full_regression.xml
.venv/Scripts/python.exe scripts/check_repository.py
```

For another regression run, use a fresh `--basetemp` and XML destination. Never
overwrite historical experiment receipts or external dataset selections.

`snapshot.py` only decomposes saved v4 evidence-family quality/mass scores. It
distinguishes unavailable dimensions, observed zero support, and verified
contradictions, and reports target-difference soft proxies separately. Unlabeled
background and hard-negative-touching pairs without explicit pair labels are
never asserted to be ground-truth negatives.

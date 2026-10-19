"""Isolate legacy tests' output writes without changing their assertions."""
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'outputs/v5_preformula_candidate_recovery/regression_isolated'


def pytest_collection_modifyitems(items):
    modules={item.module.__name__:item.module for item in items}
    capacity=modules.get('test_cptc_capacity_repair')
    if capacity:
        target=OUT/'cptc_capacity_minimal'
        # Only these four immutable inputs are used by the reference fixtures.
        # Do not clone unrelated historical spills or rebuild original receipts.
        for relative in ('protected_files_before.json','reference/backend/app/correlation/index.py',
                         'reference/backend/app/correlation/candidates.py','reference/backend/app/dedup_grouping.py'):
            dest=target/relative
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(capacity.OUT/relative,dest)
        capacity.OUT=target
    selection=modules.get('test_cptc_t5_dev_10k')
    if selection:
        selection.selection.OUT=OUT/'cptc_selection'
        selection.selection.DEST=OUT/'cptc_selection_data/suricata_alert_t5_dev_10k.json.gz'

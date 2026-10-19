"""Redirect only legacy test output mutations; assertions stay in test modules."""
from pathlib import Path
import shutil
from . import OUT


def pytest_collection_modifyitems(items):
    modules = {item.module.__name__.split('.')[-1]: item.module for item in items}
    capacity = modules.get('test_cptc_capacity_repair')
    if capacity:
        target = OUT / 'regression_isolated/cptc_capacity'
        for relative in ('protected_files_before.json', 'reference/backend/app/correlation/index.py',
                         'reference/backend/app/correlation/candidates.py', 'reference/backend/app/dedup_grouping.py'):
            dest = target / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(capacity.OUT / relative, dest)
        capacity.OUT = target
    selection = modules.get('test_cptc_t5_dev_10k')
    if selection:
        selection.selection.OUT = OUT / 'regression_isolated/cptc_selection'
        selection.selection.DEST = OUT / 'regression_isolated/cptc_selection_data/suricata_alert_t5_dev_10k.json.gz'

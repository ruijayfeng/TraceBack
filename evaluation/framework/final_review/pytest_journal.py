"""Read-only pytest observer: retain per-test outcomes even after native crashes."""
import json
import os
from pathlib import Path


def pytest_runtest_logreport(report):
    path=os.environ.get('TRACEBACK_REVIEW_JOURNAL')
    if not path:return
    record=dict(nodeid=report.nodeid,when=report.when,outcome=report.outcome,
        duration=report.duration,longrepr=str(report.longrepr) if report.longrepr else None)
    with Path(path).open('a',encoding='utf8') as f:
        f.write(json.dumps(record,ensure_ascii=False)+'\n')


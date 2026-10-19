"""Only redirect legacy test result destinations; retain every assertion/input.

This is the same output-isolation pattern already used by repository regression
plugins. A write guard prevents any further historical output/data mutation.
"""
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[3]
BLOCKED=[os.path.normcase(os.path.abspath(str(ROOT/n))) for n in ('outputs','data')]
BLOCKED.append(os.path.normcase(os.path.abspath(str(ROOT.parent/'TraceBack-Dataset'))))
SELECTION_TEMPS=[]


def protected(path):
    if not isinstance(path,(str,bytes,os.PathLike)):return False
    name=os.path.normcase(os.path.abspath(os.fsdecode(path)))
    return any(name==base or name.startswith(base+os.sep) for base in BLOCKED)


def guard(event,args):
    if event=='open':
        mode=args[1] or '';flags=args[2]
        writing=any(x in mode for x in 'wax+') if isinstance(mode,str) else False
        writing=writing or bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        if writing and protected(args[0]):raise PermissionError('historical_write_blocked:'+os.fsdecode(args[0]))
    elif event in {'os.remove','os.rmdir','os.rename','os.replace','os.truncate','os.chmod','os.utime'}:
        if any(protected(x) for x in args[:2]):raise PermissionError('historical_mutation_blocked:'+str(args[:2]))
    elif event=='os.mkdir' and protected(args[0]) and not os.path.isdir(args[0]):
        raise PermissionError('historical_directory_write_blocked:'+os.fsdecode(args[0]))


def pytest_sessionstart(session):
    sys.addaudithook(guard)


def pytest_collection_modifyitems(items):
    base=Path(os.environ['TRACEBACK_REVIEW_LEGACY_OUTPUT'])
    modules={item.module.__name__.split('.')[-1]:item.module for item in items}
    capacity=modules.get('test_cptc_capacity_repair')
    if capacity:
        target=base/'capacity'
        for name in ('protected_files_before.json','reference/backend/app/correlation/index.py',
                     'reference/backend/app/correlation/candidates.py','reference/backend/app/dedup_grouping.py'):
            dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(capacity.OUT/name,dest)
        capacity.OUT=target
    selection=modules.get('test_cptc_t5_dev_10k')
    if selection:
        # This script requires DEST.relative_to(ROOT), and its own tripwire
        # forbids any path component named evaluation. Use an owned temporary
        # directory inside ROOT, archive it afterward, and remove only that dir.
        local=Path(tempfile.mkdtemp(dir=ROOT,prefix='.traceback-v52-test-'))
        SELECTION_TEMPS.append(local)
        selection.selection.OUT=local/'selection'
        selection.selection.DEST=local/'selection_data/suricata_alert_t5_dev_10k.json.gz'


def pytest_sessionfinish(session,exitstatus):
    for local in SELECTION_TEMPS:
        resolved=local.resolve()
        if resolved.parent!=ROOT.resolve() or not resolved.name.startswith('.traceback-v52-test-'):
            raise ValueError('unsafe_owned_test_temp_cleanup')
        dest=Path(os.environ['TRACEBACK_REVIEW_LEGACY_OUTPUT'])/'selection_tree'
        shutil.copytree(resolved,dest)
        shutil.rmtree(resolved)

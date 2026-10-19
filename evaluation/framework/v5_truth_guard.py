"""Fail-closed Python file-read guard for trusted frozen replay workers.

This is an audit tripwire, not an OS sandbox against hostile native extensions.
Create the worker before loading truth; pass only explicitly allowed alert files.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sys

TRUTH_KEYS = frozenset({'truth_progression_id', 'true_edges', 'attack_stage',
    'scenario', 'scenario_labels', 'scenario_step', 'scenario_stage', 'campaign_id',
    'known_campaign_id', 'ground_truth', 'ground_truth_label', 'expected_predecessor',
    'expected_successor', 'manual_relation', 'time_label', 'event_label'})


def reject_truth_fields(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace('-', '_').replace(' ', '_') in TRUTH_KEYS:
                raise PermissionError('truth field in algorithm input: ' + key)
            reject_truth_fields(item)
    elif isinstance(value, list):
        for item in value:
            reject_truth_fields(item)


@contextmanager
def truth_guard(*, data_files, code_roots=(), write_root=None):
    """Deny reads outside exact inputs/import roots; deny child process bypasses."""
    allowed = {Path(x).resolve() for x in data_files}
    roots = tuple(Path(x).resolve() for x in code_roots)
    destination = Path(write_root).resolve() if write_root else None
    active = [True]
    events = []

    def audit(event, args):
        if not active[0]:
            return
        if event in {'subprocess.Popen', 'os.system', 'os.spawn', 'os.posix_spawn'}:
            events.append(dict(event=event, rejected=True))
            raise PermissionError('child process forbidden during blind replay')
        if event != 'open':
            return
        target, mode, flags = args
        if isinstance(target, int):
            # Pre-opened descriptors must never carry truth into a fresh worker.
            raise PermissionError('preopened file descriptor forbidden')
        path = Path(os.fsdecode(target)).resolve()
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        importing = path.suffix in {'.py', '.pyc', '.pyd', '.dll'} and any(path.is_relative_to(r) for r in roots)
        permitted = (destination is not None and path.is_relative_to(destination)) if writing else (path in allowed or importing)
        if not permitted:
            events.append(dict(event=event, path=str(path), rejected=True))
            raise PermissionError('non-allowlisted replay file: ' + str(path))
    sys.addaudithook(audit)
    try:
        yield events
    finally:
        active[0] = False

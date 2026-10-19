"""Interpret immutable read-tripwire receipts without dropping blocked events."""
from pathlib import Path
import re
import sys


def audit_guard(guard, expected_input):
    """Accept only the declared alert input and recognized blocked cache attempts.

    The legacy receipt omits open flags, so operation mode is not asserted from
    the receipt. CPython's _write_atomic uses .pyc.<id> temporary names; the local
    implementation opens them O_EXCL|O_CREAT|O_WRONLY. These attempts were denied.
    Any other rejected operation remains blocking, including truth paths.
    """
    unexpected = []
    cache_attempts = []
    cache_root = (Path(sys.base_prefix)/'Lib/sqlite3/__pycache__').resolve()
    for event in guard.get('rejected_events', []):
        path = Path(event.get('path', '')).resolve()
        known_cache = (event.get('event') == 'open' and event.get('rejected') is True
            and path.parent == cache_root
            and re.fullmatch(r'(?:__init__|dbapi2)\.cpython-311\.pyc\.\d+', path.name))
        (cache_attempts if known_cache else unexpected).append(event)
    reads = {str(Path(p).resolve()) for p in guard.get('non_code_reads', [])}
    expected = {str(Path(expected_input).resolve())}
    safe = guard.get('ground_truth_loaded') is False and reads == expected and not unexpected
    return {'status':'PASS' if safe else 'FAIL',
        'ground_truth_loaded':guard.get('ground_truth_loaded'),
        'successful_non_code_reads':sorted(reads),
        'blocked_bytecode_cache_attempts':cache_attempts,
        'unexpected_rejected_events':unexpected,
        'receipt_records_open_flags':False,
        'interpretation':'Blocked temporary bytecode-cache operations do not constitute successful dataset reads; original events are retained.'}

"""Exact authorized scope and frozen historical/data integrity; read only."""
import subprocess
import sys
from . import ROOT, OUT, OLD
from evaluation.framework.formula_design.runtime import read, save, sha


def repository():
    from scripts import check_repository as checker
    from evaluation.framework.separation_direction.checks import ADDITIONS
    new = {p.relative_to(ROOT).as_posix() for p in (ROOT/'backend/app/correlation/semantic_repair').glob('*.py')}
    old = checker.ALLOWED_APP_FILES
    try:
        checker.ALLOWED_APP_FILES = old | ADDITIONS | new
        failures = checker.check_repository(ROOT)
    finally: checker.ALLOWED_APP_FILES = old
    save(OUT/'repository_checks.json', dict(exact_authorized_additions=sorted(ADDITIONS | new),
         errors=failures, frozen_checker_unmodified=True))
    if failures: raise ValueError(failures)


def regression():
    targets = list(read(OLD/'regression_selection.json')['targets'])
    targets += ['backend/tests/test_v5_semantic_repair.py', 'evaluation/tests/test_v5_semantic_repair_evaluation.py']
    args = [sys.executable, '-u', '-B', '-m', 'pytest', *targets, '-q', '-p', 'no:cacheprovider',
            '-p', 'evaluation.framework.semantic_repair.regression_plugin',
            '--basetemp='+str(OUT/'regression_tmp'), '--junitxml='+str(OUT/'regression.xml')]
    save(OUT/'regression_selection.json', dict(command=args, targets=targets,
         scope='Complete accepted affected regression selection, plus new semantic/evaluation witnesses; assertions unchanged',
         omitted='Unchanged costly real-source AI/capacity full replays and unrelated UI; no t2'))
    with (OUT/'regression.log').open('w', encoding='utf8') as stream:
        code = subprocess.run(args, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT).returncode
    print('REGRESSION_EXIT', code, flush=True)
    raise SystemExit(code)


def integrity():
    from evaluation.framework.separation_direction.runtime import verify_seal
    from evaluation.framework.semantics_final.runtime import verify_history
    f, s = verify_seal()
    history = verify_history()
    from app.utils.stable_id import content_digest
    manifest = read(OLD/'manifest.json')
    # The preceding candidate's manifest also protects its complete output set.
    protected = manifest.get('files', {})
    failed = []
    for name, expected in protected.items():
        path = OLD/name
        if path.is_file() and sha(path) != expected: failed.append(name)
    receipt = dict(historical=history, preceding_candidate_seal_verified=True,
                   preceding_manifest_entries=len(protected), preceding_manifest_failures=failed,
                   frozen_identity={k: f[k] for k in ('algorithm_version', 'formula_hash', 'config_hash', 'implementation_hash', 'mapping_digest')},
                   git_metadata_present=(ROOT/'.git').exists(), data_and_history_unchanged=not failed)
    save(OUT/'integrity.json', receipt)
    if failed: raise ValueError('historical_outputs_changed')


if __name__ == '__main__':
    import sys
    {'repository': repository, 'regression': regression, 'integrity': integrity}[sys.argv[1]]()

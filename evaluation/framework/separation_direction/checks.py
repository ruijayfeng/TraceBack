"""Read-only repository checks with the exact explicitly authorized additions."""
from . import ROOT,OUT
from evaluation.framework.formula_design.runtime import save
from scripts import check_repository as accepted

ADDITIONS={
    'backend/app/correlation/separation_direction/__init__.py',
    'backend/app/correlation/separation_direction/evidence.py',
    'backend/app/correlation/separation_direction/formula.py',
    'backend/app/correlation/separation_direction/direction.py',
    'backend/app/correlation/separation_direction/models.py',
    'backend/app/correlation/separation_direction/graph.py',
}


def run():
    original=accepted.check_repository(ROOT)
    previous=accepted.ALLOWED_APP_FILES
    try:
        accepted.ALLOWED_APP_FILES=previous|ADDITIONS
        scoped=accepted.check_repository(ROOT)
    finally:accepted.ALLOWED_APP_FILES=previous
    save(OUT/'repository_checks.json',dict(legacy_errors=original,authorized_candidate_additions=sorted(ADDITIONS),
        scoped_errors=scoped,original_checker_unmodified=True,
        method='Extend exact task scope in memory; all frozen-document, forbidden-import and isolation checks retained.'))
    if scoped:raise ValueError(scoped)
    print('AUTHORIZED_SCOPE_REPOSITORY_CHECK_PASS',flush=True)


if __name__=='__main__':run()

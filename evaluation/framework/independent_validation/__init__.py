"""Single-use frozen Candidate C validation; never installed in production."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_independent_validation'
DATA = ROOT.parent / 'TraceBack-Dataset/data/traceback_independent_validation_v1'

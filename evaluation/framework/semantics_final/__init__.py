"""Single-candidate final semantics calibration; experiment output is isolated."""
from pathlib import Path
import os
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(os.environ.get('TRACEBACK_SEMANTICS_OUT',ROOT/'outputs/v5_evidence_semantics_final'))

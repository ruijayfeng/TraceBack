"""V5 score/admission research over sealed observations; no production deployment."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'outputs/v5_source_bound_observability_final'
OUT = ROOT / 'outputs/v5_scoring_calibration'
POLICY = ROOT / 'evaluation/configs/scoring_calibration.yaml'

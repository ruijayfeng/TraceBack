"""Offline formula research. Never imported by the production application."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_formula_design'
BASELINE = ROOT / 'outputs/v5_preformula_baseline'
POLICY = ROOT / 'evaluation/configs/v5_formula_design.yaml'

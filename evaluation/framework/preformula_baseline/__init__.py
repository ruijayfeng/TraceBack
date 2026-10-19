"""Versioned V5 pre-formula integration; no scoring implementation lives here."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_preformula_baseline'
VERSION = 'alert-correlation-v5-preformula-candidate-v1'
IDENTITY = 'v5-preformula-candidate-v1'
PREVIOUS = ROOT / 'outputs/v5_preformula_candidate_recovery'

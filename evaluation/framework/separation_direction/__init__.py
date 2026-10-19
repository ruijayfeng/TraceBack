"""Development-only, post-seal evaluation of a separately versioned candidate."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_separation_direction'
BASE = ROOT / 'outputs/v5_evidence_semantics_final'
INPUT = ROOT / 'outputs/v5_preformula_baseline/blind'

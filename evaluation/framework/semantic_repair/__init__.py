"""User-authorized development comparison and separately sealed final replay."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_semantic_repair'
OLD = ROOT / 'outputs/v5_separation_direction'
INPUT = ROOT / 'outputs/v5_preformula_baseline/blind'
POLICY = ROOT / 'configs/algorithm-v5-semantic-repair.yaml'

"""Delegate the offline report to evaluation without importing truth code."""
from pathlib import Path
import subprocess
import sys

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    raise SystemExit(subprocess.call([sys.executable,'-m',
        'evaluation.framework.correlation_quality_audit.v3_repair_report',*sys.argv[1:]],cwd=root))

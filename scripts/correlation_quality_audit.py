"""Launch offline evaluation in a separate process; no evaluation imports here.

The repository prohibits evaluation imports in scripts/ as well as production.
All audit and GT access stays under evaluation/**, in the child process.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def main():
    return subprocess.call([sys.executable, "-m", "evaluation.framework.correlation_quality_audit.cli", *sys.argv[1:]], cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())

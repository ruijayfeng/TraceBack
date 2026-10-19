"""One-command real TraceBack demo; orchestration only, no algorithm rules."""

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    # The repository runtime is 3.11; Windows' unqualified python may be 3.10.
    if sys.version_info[:2] != (3, 11):
        runtime = ROOT / (".venv/Scripts/python.exe" if sys.platform == "win32" else ".venv/bin/python")
        if runtime.is_file() and runtime.resolve() != Path(sys.executable).resolve():
            return subprocess.call([str(runtime), str(Path(__file__).resolve()), *sys.argv[1:]], cwd=ROOT)
        print("FAILED [Python]: Python 3.11 required. Install/activate the README environment.", file=sys.stderr)
        return 1
    sys.path.insert(0, str(ROOT / "backend"))
    from demo_support import run_demo, serve
    parser = argparse.ArgumentParser(description="Run one registered Dataset / Scene production analysis and API")
    parser.add_argument("--dataset", default="ait_ads", help="Dataset registry ID (default: ait_ads)")
    parser.add_argument("--scene", help="Scene ID (default: registry default_scene)")
    parser.add_argument("--check-only", action="store_true", help="Validate environment/data/config/storage without analysis")
    parser.add_argument("--analysis-id", metavar="ANALYSIS_ID", help="Validate and open an explicit real Analysis snapshot")
    parser.add_argument("--cold-rebuild", action="store_true", help="Run the existing full production service, creating a new isolated snapshot")
    parser.add_argument("--warm-only", action="store_true", help="Require a matching snapshot; never start a cold analysis")
    parser.add_argument("--serve", metavar="ANALYSIS_ID", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        return serve(ROOT, args.serve, args.port)
    if args.cold_rebuild and (args.analysis_id or args.warm_only):
        parser.error("--cold-rebuild cannot be combined with snapshot options")
    return run_demo(ROOT, check_only=args.check_only, analysis_id=args.analysis_id,
                    cold_rebuild=args.cold_rebuild, warm_only=args.warm_only,
                    dataset_id=args.dataset, scene_id=args.scene)


if __name__ == "__main__":
    raise SystemExit(main())

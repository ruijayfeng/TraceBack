"""Offline-only audit entrypoint; labels remain inside evaluation/**."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))

from .correlation_quality import capture_integrity, write_json, read_json, digest
from .correlation_run import run_audit, finalize


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-before", action="store_true")
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--receipt", default="outputs/correlation_v2/REAL_DATA_RESULT.json")
    parser.add_argument("--destination", default="outputs/correlation_quality_audit")
    parser.add_argument("--verify-upgrade-integrity", action="store_true")
    args = parser.parse_args()
    destination = (ROOT / args.destination).resolve()
    receipt = (ROOT / args.receipt).resolve()
    if not destination.is_relative_to(ROOT / "outputs") or not receipt.is_relative_to(ROOT / "outputs"):
        raise ValueError("audit_output_scope")
    destination.mkdir(parents=True, exist_ok=True)
    if args.verify_upgrade_integrity:
        target = ROOT / "outputs/correlation_v3"
        baseline = read_json(target / "before_hashes.json")
        freeze = read_json(target / "implementation_freeze.json")
        after = {}
        for number, path in enumerate(sorted(baseline), 1):
            after[path] = digest(ROOT / path)
            if number % 100 == 0:
                print(f"upgrade integrity {number}/{len(baseline)}", flush=True)
        changed = sorted(p for p in baseline if baseline[p] != after[p])
        unexpected = sorted(set(changed) - set(freeze["production"]))
        frozen_mismatch = sorted(p for p, expected in freeze["production"].items() if digest(ROOT / p) != expected)
        result = dict(historical_unchanged=not unexpected, frozen_v3_sources_match=not frozen_mismatch,
            baseline_file_count=len(baseline), unchanged_file_count=len(baseline)-len(changed),
            authorized_implementation_changes=changed, unexpected_changes=unexpected,
            frozen_v3_mismatch=frozen_mismatch,
            old_snapshot_files_verified=sum(p.startswith(("data/processed/", "outputs/analyses/")) for p in baseline),
            v2_receipt_and_audit_files_verified=sum(p.startswith(("outputs/correlation_v2/", "outputs/correlation_quality_audit/")) for p in baseline),
            files={p:dict(before_sha256=baseline[p],after_sha256=after[p],equal=baseline[p]==after[p]) for p in baseline})
        write_json(target / "snapshot_integrity.json", result)
        if unexpected or frozen_mismatch:
            raise ValueError("upgrade_integrity_failed")
        print("all historical artifacts unchanged; only enumerated v3 production changes",flush=True)
    elif args.capture_before:
        target = destination / "before_hashes.json"
        if target.exists():
            raise ValueError("before_hashes_already_exist_do_not_overwrite")
        write_json(target, capture_integrity(ROOT))
        print("before hashes captured", flush=True)
    elif args.finalize:
        finalize(ROOT, destination)
    else:
        run_audit(ROOT, destination, receipt=receipt)


if __name__ == "__main__":
    main()

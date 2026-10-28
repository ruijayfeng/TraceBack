"""Read-only Task 01–05 checks; never read dataset or Ground Truth content."""

from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import tomllib


REQUIRED_DIRS = (
    "backend/app/adapters", "backend/app/models", "backend/app/entities", "backend/app/dedup",
    "backend/app/correlation", "backend/app/incidents", "backend/app/chains", "backend/app/ai",
    "backend/app/api", "backend/app/services", "backend/tests/fixtures", "frontend",
    "evaluation", "configs/mappings", "data/input/alerts", "data/processed", "scripts", "docs",
)
REQUIRED_FILES = (
    "README.md", ".gitignore", ".editorconfig", "backend/pyproject.toml",
    "backend/app/__init__.py", "backend/app/config.py", "backend/tests/conftest.py",
    "backend/tests/test_config.py", "backend/tests/test_repository_contract.py",
    "configs/algorithm-v0.yaml", "configs/sources.yaml", "scripts/check_repository.py",
)
FROZEN_DOCUMENTS = {
    # Baselines reflect the user-authorized nine-stage plan; original requirements unchanged.
    "AGENTS.md": "fa0136789d1b2957cef896e4f8c6e2409babce8311099061e72d308fb4d58d50",
    "docs/TraceBack-统一需求文档-1-20.md": "caf8ff7032de4b3c1b4e0e25d586ee3182bbe94a351ff706d3340a23432229b2",
    "docs/TraceBack-统一需求文档-21-37.md": "d84e986a5a80fac8803133be45d6ecef2ca2a00944bc5748a844aedb391f3101",
    "docs/TraceBack-统一需求文档-38-42.md": "0b4489e8f61107ac86a463503af3b3c492ce8bd705b51f3f926e97d237ec767d",
    "docs/DATA_CONTRACT.md": "72a73293db2267f1accdfb7d4063a8df2f70361b09bbe592df7b2e80602f8a26",
    # Only document hashes updated; bootstrap checks are unchanged.
    "docs/ALGORITHM_CONFIG.md": "014ca4216b07261e8df693dbd1b20de5306dabb437248cbeace04a4476461e2a",
    "docs/CODEX_TASKS.md": "500a34126f15776bf0c730f57b893c438a837b0aae56777424c93ed45afb6610",
}
BANNED_MODULES = {
    "evaluation", "kafka", "flink", "pyflink", "spark", "pyspark", "elasticsearch", "neo4j",
    "kubernetes", "torch", "tensorflow", "torch_geometric", "dgl", "sklearn",
}
BANNED_DIRECTORIES = {
    "detectors", "detector_framework", "raw_log_parser", "log_parser", "canonical_events",
    "behavior_findings", "behavior_discovery", "evidence_expansion",
    "kafka", "flink", "spark", "elasticsearch", "neo4j", "kubernetes", "gnn",
}
ALLOWED_RUNTIME = {"pydantic", "pyyaml", "annotated-types", "typing-extensions", "typing-inspection", "duckdb", "fastapi", "uvicorn", "httpx"}
ALLOWED_TEST = {"pytest", "iniconfig", "packaging", "pluggy", "pygments", "colorama", "httpx", "jsonschema"}

# Preserve existing foundations; allow only the exact authorized Task 03 files.
ALLOWED_APP_FILES = {
    # Exact user-authorized Stage 1–4 orchestration and shared truth contract.
    'backend/app/services/alert_pipeline.py', 'backend/app/adapters/truth.py',
    # Exact user-authorized CanonicalAlert -> noise filter -> kept alerts.
    "backend/app/noise_filter/__init__.py", "backend/app/noise_filter/config.py",
    "backend/app/noise_filter/filter.py", "backend/app/noise_filter/models.py",
    # User-authorized front-data handoff; no downstream algorithm changes.
    "backend/app/services/front_data.py",
    # Exact user-authorized V5 formula and final evidence-semantics repair.
    "backend/app/correlation/formula_v5.py", "backend/app/correlation/evidence_v5.py",
    "backend/app/correlation/evidence_semantics.py",
    # User-authorized V5 pre-formula projection and role-aware candidate recovery.
    "backend/app/adapters/wazuh_semantics.py", "backend/app/correlation/entity_bridges.py",
    "backend/app/services/capacity.py",
    # Task B.1 explicit dependency-closure/mutable-workspace authorization.
    "backend/app/services/incremental.py",
    "backend/app/services/incremental_dependencies.py",
    "backend/app/services/incremental_store.py",
    # User-authorized Correlation v3 evidence quality repair.
    "backend/app/dedup/observation.py", "backend/app/correlation/evidence_v3.py",
    "backend/app/correlation/evidence_v4.py",
    "backend/app/models/correlation_v3.py",
    # Exact user-authorized bounded streaming diagnostic persistence module.
    "backend/app/services/bounded_diagnostics.py",
    "backend/app/__init__.py", "backend/app/config.py",
    "backend/app/utils/__init__.py", "backend/app/utils/stable_id.py",
    "backend/app/adapters/base.py", "backend/app/adapters/wazuh.py",
    "backend/app/adapters/aminer.py", "backend/app/adapters/__init__.py",
    # Explicit CPTC-2018 Step 2 authorization: native EVE + export reader only.
    "backend/app/adapters/suricata.py", "backend/app/adapters/cptc.py",
    # User-authorized source-bound projection audit (observed native schemas).
    "backend/app/adapters/multisource.py",
    "backend/app/services/normalization.py", "backend/app/services/__init__.py",
    "backend/app/services/storage.py",
    "backend/app/correlation/__init__.py", "backend/app/correlation/index.py",
    "backend/app/correlation/candidates.py", "backend/app/correlation/scoring.py",
    "backend/app/correlation/reasons.py", "backend/app/correlation/conflicts.py",
    "backend/app/correlation/edges.py",
    # Explicitly authorized Task 04 modules; no future-stage tree wildcard.
    "backend/app/incidents/__init__.py", "backend/app/incidents/clustering.py",
    "backend/app/chains/__init__.py", "backend/app/chains/nodes.py",
    "backend/app/chains/reconstruction.py", "backend/app/chains/direction.py",
    "backend/app/chains/conflicts.py", "backend/app/chains/assembly.py",
    "backend/app/chains/grounding.py",
    # Exact Task 05 registration; future AI/front-end/evaluation files stay closed.
    "backend/app/main.py", "backend/app/services/analysis.py", "backend/app/services/queries.py",
    "backend/app/api/__init__.py", "backend/app/api/schemas.py", "backend/app/api/routes.py",
    # Exact Task 07.1 registration; ATT&CK/report/UI and unknown AI files stay closed.
    "backend/app/ai/__init__.py", "backend/app/ai/provider.py",
    "backend/app/ai/explanation.py", "backend/app/ai/grounding.py",
    "backend/app/ai/prompts/__init__.py", "backend/app/ai/providers/__init__.py",
    "backend/app/ai/providers/fake.py", "backend/app/ai/providers/openai_compatible.py",
    "backend/app/api/explanations.py",
    # Exact user-authorized Task 07.2 files; unknown AI files remain closed.
    "backend/app/ai/attack_catalog/__init__.py", "backend/app/ai/report.py",
    # Task 08 presentation files; frozen production implementations unchanged.
    "backend/app/api/workbench.py", "backend/app/api/workbench_store.py",
    # Task 09.1: user-authorized, read-only metric / score diagnostic helpers.
    "backend/app/api/incident_metrics.py", "backend/app/api/score_diagnostics.py",
    # User-authorized AIT-ADS registry; no scoring or GT reader.
    "backend/app/services/datasets.py",
    # User-authorized correlation v2 upgrade and independent singleton triage.
    "backend/app/correlation/evidence.py", "backend/app/incidents/triage.py",
}
ALLOWED_APP_TREES = (
    "backend/app/models/", "backend/app/entities/", "backend/app/dedup/",
)


def authorized_app_file(relative: str) -> bool:
    return relative in ALLOWED_APP_FILES or relative.startswith(ALLOWED_APP_TREES)


def _dependency_name(requirement: str) -> str:
    match = re.match(r"^[A-Za-z0-9_.-]+", requirement)
    return match.group(0).lower().replace("_", "-") if match else ""


def check_repository(root: Path) -> list[str]:
    """Return contract violations; only source/config/document metadata are inspected."""
    root = root.resolve()
    errors = []
    for name in REQUIRED_DIRS:
        if not (root / name).is_dir():
            errors.append(f"missing directory: {name}")
    for name in REQUIRED_FILES:
        if not (root / name).is_file():
            errors.append(f"missing file: {name}")
    for name, expected in FROZEN_DOCUMENTS.items():
        path = root / name
        if not path.is_file():
            errors.append(f"missing frozen document: {name}")
        elif sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f"frozen document changed: {name}")
    project_path = root / "backend/pyproject.toml"
    if project_path.is_file():
        try:
            project = tomllib.loads(project_path.read_text(encoding="utf-8"))
            metadata = project["project"]
            if metadata.get("requires-python") != ">=3.11,<3.12":
                errors.append("Python contract must be >=3.11,<3.12")
            for requirement in metadata.get("dependencies", []):
                if _dependency_name(requirement) not in ALLOWED_RUNTIME or "==" not in requirement:
                    errors.append(f"unapproved/unpinned runtime dependency: {requirement}")
            for group in metadata.get("optional-dependencies", {}).values():
                for requirement in group:
                    if _dependency_name(requirement) not in ALLOWED_TEST or "==" not in requirement:
                        errors.append(f"unapproved/unpinned test dependency: {requirement}")
            if project["build-system"] != {
                "requires": ["setuptools==80.9.0"], "build-backend": "setuptools.build_meta"
            }:
                errors.append("build backend/environment differs from pinned bootstrap")
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"invalid project metadata: {exc}")
    # Do not traverse .venv, data, outputs, or dataset labels.
    for base in (root / "backend/app", root / "frontend", root / "scripts"):
        for path in base.rglob("*"):
            if path.is_dir() and path.name.lower() in BANNED_DIRECTORIES:
                errors.append(f"banned directory: {path.relative_to(root)}")
            if not path.is_file() or path.suffix != ".py":
                continue
            relative = path.relative_to(root).as_posix()
            if relative.startswith("backend/app/") and not authorized_app_file(relative):
                errors.append(f"business code outside authorized Task 01/02/03/04/05 scope: {relative}")
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                errors.append(f"invalid Python: {relative}: {exc}")
                continue
            for node in ast.walk(tree):
                imports = []
                if isinstance(node, ast.Import):
                    imports = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports = [node.module]
                if any(name.split(".")[0] in BANNED_MODULES for name in imports):
                    errors.append(f"banned import: {relative}:{node.lineno}")
    frontend_files = {"package.json", "package-lock.json", "tsconfig.json", "vite.config.ts", "index.html", "playwright.config.ts", "tsconfig.tsbuildinfo", ".gitkeep"}
    frontend_trees = ("src/", "e2e/", "node_modules/", "dist/", "test-results/", "playwright-report/")
    for path in (root / "frontend").glob("*"):
        relative = path.relative_to(root / "frontend").as_posix()
        if relative in frontend_files or any(relative + "/" == tree for tree in frontend_trees):
            continue
        errors.append(f"frontend business outside Task 001: {path.relative_to(root)}")
    package = root / "frontend/package.json"
    if package.is_file():
        try:
            metadata = json.loads(package.read_text(encoding="utf-8"))
            for dependency in metadata.get("dependencies", {}):
                if dependency not in {"react", "react-dom"}:
                    errors.append(f"unapproved frontend runtime dependency: {dependency}")
        except (ValueError, OSError):
            errors.append("invalid frontend package metadata")
    return sorted(set(errors))


def main() -> int:
    errors = check_repository(Path(__file__).resolve().parents[1])
    if sys.version_info[:2] != (3, 11):
        errors.append("repository checks must run with Python 3.11")
    print(json.dumps({"status": "failed" if errors else "passed", "errors": errors},
                     ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

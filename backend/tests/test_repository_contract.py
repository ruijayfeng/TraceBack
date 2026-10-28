"""Repository and isolation checks for the authorized Task 01–05 scope."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from app.config import ConfigurationError, load_config, read_yaml


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("repository_contract", ROOT / "scripts/check_repository.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def test_repository_contract():
    assert contract.check_repository(ROOT) == []


def test_repository_command_smoke():
    result = subprocess.run([sys.executable, "scripts/check_repository.py"], cwd=ROOT,
                            capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {"status": "passed", "errors": []}


@pytest.mark.parametrize("module", ["adapters/suricata.py", "adapters/cptc.py"])
def test_exact_cptc_step2_modules_are_authorized(contract_copy, module):
    (contract_copy / "backend/app" / module).write_text("# synthetic CPTC Step 2 fixture\n", encoding="utf-8")
    assert contract.check_repository(contract_copy) == []


def test_cptc_authorization_does_not_open_arbitrary_adapters(contract_copy):
    (contract_copy / "backend/app/adapters/future_cptc.py").write_text("# synthetic unauthorized module\n", encoding="utf-8")
    assert any("business code outside authorized" in e for e in contract.check_repository(contract_copy))


def test_python_and_pinned_parser_test_versions():
    from importlib.metadata import version
    assert sys.version_info[:2] == (3, 11)
    for package, expected in {"pydantic": "2.11.7", "pydantic-core": "2.33.2",
                              "PyYAML": "6.0.2", "pytest": "8.4.1", "duckdb": "1.4.1"}.items():
        assert version(package) == expected


def test_schema_validator_is_declared_for_tests_and_optional_prototype():
    import tomllib
    from importlib.metadata import version
    project = tomllib.loads((ROOT / 'backend/pyproject.toml').read_text(encoding='utf8'))['project']
    for extra in ('test', 'prototype'):
        assert 'jsonschema==4.23.0' in project['optional-dependencies'][extra]
    assert not any(dep.startswith('jsonschema') for dep in project['dependencies'])
    assert version('jsonschema') == '4.23.0'


@pytest.mark.parametrize("module", ["main.py", "services/analysis.py", "services/queries.py",
                                    "api/__init__.py", "api/schemas.py", "api/routes.py"])
def test_exact_task05_scope_is_allowed(contract_copy, module):
    path = contract_copy / "backend/app" / module
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# synthetic Task 05 scope fixture\n", encoding="utf-8")
    assert contract.check_repository(contract_copy) == []


@pytest.mark.parametrize("module", ["services/analysis.py", "services/queries.py", "api/routes.py"])
def test_task05_authorization_preserves_gt_import_isolation(contract_copy, module):
    path = contract_copy / "backend/app" / module
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("import evaluation.io\n", encoding="utf-8")
    assert any("banned import" in error for error in contract.check_repository(contract_copy))


def test_dependency_versions_and_task071_httpx_runtime_scope():
    import tomllib
    from importlib.metadata import version
    metadata = tomllib.loads((ROOT/"backend/pyproject.toml").read_text(encoding="utf-8"))["project"]
    for package, expected in {"fastapi": "0.115.14", "uvicorn": "0.35.0", "httpx": "0.28.1"}.items():
        assert version(package) == expected
    assert "fastapi==0.115.14" in metadata["dependencies"]
    assert "uvicorn==0.35.0" in metadata["dependencies"]
    assert "httpx==0.28.1" in metadata["optional-dependencies"]["test"]
    assert "httpx==0.28.1" in metadata["dependencies"]


@pytest.fixture
def contract_copy(tmp_path):
    # Only copy document/code metadata; never copy/read data or Ground Truth.
    for relative in (*contract.REQUIRED_FILES, *contract.FROZEN_DOCUMENTS):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    for relative in contract.REQUIRED_DIRS:
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    assert contract.check_repository(tmp_path) == []
    return tmp_path


def test_missing_directory_is_reported(contract_copy):
    (contract_copy / "backend/app/chains").rmdir()
    assert "missing directory: backend/app/chains" in contract.check_repository(contract_copy)


@pytest.mark.parametrize("dependency", ["kafka-python==2.0.2", "pyflink==1.0.0", "pyspark==1.0.0",
                                        "elasticsearch==1.0.0", "neo4j==1.0.0", "kubernetes==1.0.0",
                                        "torch-geometric==1.0.0", "scikit-learn==1.0.0", "PyYAML"])
def test_banned_or_unpinned_dependency_is_reported(contract_copy, dependency):
    path = contract_copy / "backend/pyproject.toml"
    path.write_text(path.read_text(encoding="utf-8").replace(
        '"pydantic==2.11.7",', f'"pydantic==2.11.7",\n    "{dependency}",'), encoding="utf-8")
    assert any("unapproved/unpinned runtime dependency" in e for e in contract.check_repository(contract_copy))


@pytest.mark.parametrize("directory", ["raw_log_parser", "detector_framework", "canonical_events",
                                       "behavior_findings", "evidence_expansion", "gnn", "neo4j"])
def test_banned_directory_is_reported(contract_copy, directory):
    (contract_copy / "backend/app" / directory).mkdir()
    assert any("banned directory" in e for e in contract.check_repository(contract_copy))


@pytest.mark.parametrize("module", ["evaluation", "evaluation.io", "neo4j", "torch_geometric"])
def test_banned_production_import_is_reported(contract_copy, module):
    path = contract_copy / "backend/app/config.py"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\nimport {module}\n")
    assert any("banned import" in e for e in contract.check_repository(contract_copy))


def test_future_business_code_is_reported(contract_copy):
    (contract_copy / "backend/app/adapters/alert.py").write_text("class FutureAdapter: pass\n", encoding="utf-8")
    (contract_copy / "frontend/App.tsx").write_text("export {};\n", encoding="utf-8")
    errors = contract.check_repository(contract_copy)
    assert any("business code outside authorized Task 01/02/03/04/05 scope" in e for e in errors)
    assert any("frontend business outside Task 001" in e for e in errors)


@pytest.mark.parametrize("module", ["incidents/clustering.py", "incidents/__init__.py", "chains/nodes.py",
    "chains/reconstruction.py", "chains/direction.py", "chains/conflicts.py", "chains/assembly.py",
    "chains/grounding.py", "chains/__init__.py", "services/storage.py"])
def test_exact_task04_scope_is_allowed(contract_copy, module):
    (contract_copy / "backend/app" / module).write_text("# synthetic allowed module\n", encoding="utf-8")
    assert contract.check_repository(contract_copy) == []


@pytest.mark.parametrize("module", ["chains/unauthorized.py", "incidents/future.py", "services/future.py",
    "services/future_query.py", "api/future.py", "ai/future_explanation.py"])
def test_task04_registration_does_not_open_future_or_unknown_files(contract_copy, module):
    (contract_copy / "backend/app" / module).write_text("# synthetic unauthorized module\n", encoding="utf-8")
    assert any("business code outside authorized" in e for e in contract.check_repository(contract_copy))


def test_frozen_document_change_is_reported(contract_copy):
    path = contract_copy / "docs/TraceBack-统一需求文档-1-20.md"
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\nsynthetic contract mutation in temporary test copy\n")
    assert "frozen document changed: docs/TraceBack-统一需求文档-1-20.md" in contract.check_repository(contract_copy)


def test_checks_do_not_read_data_or_ground_truth(monkeypatch):
    original = Path.read_bytes

    def bytes_tripwire(path):
        assert not any(p.lower() in ("data", "evaluation") for p in path.parts)
        return original(path)

    original_text = Path.read_text

    def text_tripwire(path, *args, **kwargs):
        assert not any(p.lower() in ("data", "evaluation") for p in path.parts)
        return original_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", bytes_tripwire)
    monkeypatch.setattr(Path, "read_text", text_tripwire)
    assert contract.check_repository(ROOT) == []


def test_existing_data_paths_only_existence():
    for relative in ("data/ait_ads/russellmitchell/raw/russellmitchell_aminer.json",
                     "data/ait_ads/russellmitchell/raw/russellmitchell_wazuh.json",
                     "data/ait_ads/russellmitchell/evaluation/labels.csv"):
        assert (ROOT / relative).is_file()


def test_reserved_business_directories_preserve_exact_authorized_scope():
    expected = {"__init__.py", "provider.py", "explanation.py", "grounding.py",
                "prompts/__init__.py", "providers/__init__.py", "providers/fake.py", "providers/openai_compatible.py",
                "attack_catalog/__init__.py", "report.py"}
    actual = {p.relative_to(ROOT / "backend/app/ai").as_posix() for p in (ROOT / "backend/app/ai").rglob("*.py")}
    assert actual == expected
    assert (ROOT / "backend/app/api/explanations.py").is_file()
    # Task 08 explicitly authorizes the SOC frontend, preserving the unknown
    # file/dependency rejection and exact AI file boundary above.
    assert contract.check_repository(ROOT) == []
    metadata = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    assert set(metadata["dependencies"]) == {"react", "react-dom"}
    assert {"test", "typecheck", "build"} <= metadata["scripts"].keys()
    # Existing Evaluation tree stays unchanged.
    assert {p.name for p in (ROOT / "evaluation").iterdir()} == {
        ".gitkeep", "README.md", "framework", "metrics", "io", "tests",
        "configs", "baselines", "ablation", "robustness", "sensitivity",
    }


@pytest.mark.parametrize("module", ["ai/__init__.py", "ai/provider.py", "ai/explanation.py", "ai/grounding.py",
    "ai/prompts/__init__.py", "ai/providers/__init__.py", "ai/providers/fake.py", "ai/providers/openai_compatible.py",
    "api/explanations.py"])
def test_exact_task071_files_preserve_gt_import_isolation(contract_copy, module):
    path = contract_copy / "backend/app" / module
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# synthetic exact Task 07.1 registration\n", encoding="utf-8")
    assert contract.check_repository(contract_copy) == []
    path.write_text("import evaluation.io\n", encoding="utf-8")
    assert any("banned import" in error for error in contract.check_repository(contract_copy))


@pytest.mark.parametrize("module", ["ai/future.py", "ai/attack_catalog/catalog.py", "ai/providers/future.py", "ai/report_future.py"])
def test_task071_does_not_open_next_task_or_unknown_ai_files(contract_copy, module):
    path = contract_copy / "backend/app" / module
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# synthetic unapproved future file\n", encoding="utf-8")
    assert any("business code outside authorized" in error for error in contract.check_repository(contract_copy))


@pytest.mark.parametrize("module", ["ai/attack_catalog/__init__.py", "ai/report.py"])
def test_task072_exact_files_allowed_with_gt_isolation(contract_copy, module):
    path = contract_copy / "backend/app" / module
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# synthetic Task 07.2 allowed module\n", encoding="utf-8")
    assert contract.check_repository(contract_copy) == []
    path.write_text("import evaluation.io\n", encoding="utf-8")
    assert any("banned import" in error for error in contract.check_repository(contract_copy))


@pytest.mark.parametrize("relative", [
    "adapters/base.py", "adapters/wazuh.py", "adapters/aminer.py", "adapters/__init__.py",
    "entities/extraction.py", "entities/normalization.py", "entities/helpers/scope.py",
    "dedup/candidates.py", "dedup/grouping.py", "dedup/helpers/payload.py",
    "services/normalization.py", "services/__init__.py", "services/storage.py", "correlation/index.py", "correlation/candidates.py", "correlation/scoring.py", "correlation/reasons.py", "correlation/conflicts.py", "correlation/edges.py", "correlation/__init__.py",
])
def test_task02_business_files_are_authorized(contract_copy, relative):
    path = contract_copy / "backend/app" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('"""Synthetic scope-check fixture."""\n', encoding="utf-8")
    assert contract.check_repository(contract_copy) == []


@pytest.mark.parametrize("relative", [
    "adapters/future_suricata.py", "adapters/helpers.py", "services/future.py",
    "services/normalization/extra.py", "utils/new_helper.py", "correlation/extra.py",
    "correlation/direction.py", "incidents/unauthorized.py", "chains/unauthorized.py",
    "ai/future_provider.py", "api/future_alerts.py", "entities_extra/extraction.py", "dedup_extra/grouping.py",
])
def test_business_outside_task02_remains_forbidden(contract_copy, relative):
    path = contract_copy / "backend/app" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('"""Synthetic forbidden-scope fixture."""\n', encoding="utf-8")
    assert any("business code outside authorized Task 01/02/03/04/05 scope" in error
               for error in contract.check_repository(contract_copy))


@pytest.mark.parametrize("relative", ["adapters/wazuh.py", "entities/extraction.py", "dedup/grouping.py",
                                      "services/normalization.py", "chains/grounding.py", "incidents/clustering.py"])
def test_task02_authorization_does_not_bypass_import_isolation(contract_copy, relative):
    path = contract_copy / "backend/app" / relative
    path.write_text("import evaluation.io\n", encoding="utf-8")
    assert any("banned import" in error for error in contract.check_repository(contract_copy))


def test_current_mapping_contract_baseline_is_still_frozen(contract_copy):
    path = contract_copy / "docs/ALGORITHM_CONFIG.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nsynthetic change\n", encoding="utf-8")
    assert "frozen document changed: docs/ALGORITHM_CONFIG.md" in contract.check_repository(contract_copy)


def test_nonempty_mapping_loading_never_reads_ground_truth(tmp_path, monkeypatch):
    config = read_yaml(ROOT / "configs/algorithm-v0.yaml")
    mapping = {"schema_version": "1.0", "mapping_type": "payload", "source_type": "other", "default": None,
               "rules": [{"id": "synthetic", "match": {"all": [{"field": "rule_id", "op": "eq", "value": "synthetic"}]},
                          "output": {"fields": ["url"]}}]}
    (tmp_path / "payload.yaml").write_text(yaml.safe_dump(mapping), encoding="utf-8")
    config["duplicate"]["payload_mapping_files"] = ["payload.yaml"]
    algorithm = tmp_path / "algorithm.yaml"
    algorithm.write_text(yaml.safe_dump(config), encoding="utf-8")
    original_text, original_bytes = Path.read_text, Path.read_bytes
    reads = []

    def text_tripwire(path, *args, **kwargs):
        assert not any(part.lower() in ("data", "evaluation") for part in path.parts)
        reads.append(path.name)
        return original_text(path, *args, **kwargs)

    def bytes_tripwire(path):
        assert not any(part.lower() in ("data", "evaluation") for part in path.parts)
        return original_bytes(path)

    monkeypatch.setattr(Path, "read_text", text_tripwire)
    monkeypatch.setattr(Path, "read_bytes", bytes_tripwire)
    effective = load_config(algorithm)
    assert len(effective.mapping_files["duplicate.payload_mapping_files"]) == 1
    assert "payload.yaml" in reads
    for forbidden in ("data/ait_ads/russellmitchell/evaluation/labels.csv", "evaluation/answers.yaml", "data/labels.yaml"):
        config["duplicate"]["payload_mapping_files"] = [str(ROOT / forbidden)]
        algorithm.write_text(yaml.safe_dump(config), encoding="utf-8")
        with pytest.raises(ConfigurationError, match="configuration path"):
            load_config(algorithm)
    assert not any(name in reads for name in ("labels.csv", "answers.yaml", "labels.yaml"))


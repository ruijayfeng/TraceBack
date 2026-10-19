"""Production-only dataset registry. Dataset identity never becomes score evidence."""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import yaml

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr

from app.adapters.base import AdapterSettings
from app.config import load_config, _UniqueKeyLoader
from app.services.storage import restore_config
from app.utils.stable_id import content_digest


class RegistryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SourceProfile(RegistryModel):
    format_profile: StrictStr
    generator: StrictStr
    generator_version: StrictStr
    epoch_unit: StrictStr | None
    timezone: StrictStr


class Scene(RegistryModel):
    enabled: StrictBool
    namespace: StrictStr
    network_namespace: StrictStr
    raw: dict[StrictStr, StrictStr]


class DatasetManifest(RegistryModel):
    dataset_id: StrictStr
    name: StrictStr
    dataset_version: StrictInt
    default_scene: StrictStr
    source_profiles: dict[StrictStr, SourceProfile]
    scenes: dict[StrictStr, Scene]


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", value):
        raise ValueError("invalid_dataset_or_scene_id")
    return value


def security_path(root, base, reference):
    if not isinstance(reference, str) or "\\" in reference or ":" in reference or "%" in reference:
        raise ValueError("invalid_registry_raw_path")
    relative = PurePosixPath(reference)
    if relative.is_absolute() or any(p in {"", ".", ".."} for p in reference.split("/")):
        raise ValueError("invalid_registry_raw_path")
    if "evaluation" in {p.lower() for p in relative.parts} or relative.suffix.lower() not in {".json", ".jsonl", ".ndjson"}:
        raise ValueError("registry_path_not_security_alert")
    candidate = base / reference
    if not candidate.resolve().is_relative_to(base.resolve()) or candidate.resolve() != candidate.absolute():
        raise ValueError("redirected_registry_path")
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (candidate, *candidate.parents)):
        raise ValueError("redirected_registry_path")
    return candidate.relative_to(root).as_posix()


def read_registry(root, dataset_id="ait_ads"):
    root = Path(root).resolve()
    dataset_id = identifier(dataset_id)
    base = root / "data" / dataset_id
    manifest = base / "dataset.yaml"
    if manifest.resolve() != manifest.absolute() or any(
        p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (manifest, *manifest.parents)
    ):
        raise ValueError("redirected_registry_path")
    with manifest.open(encoding="utf-8") as handle:
        document = yaml.load(handle, Loader=_UniqueKeyLoader)
    if not isinstance(document, dict):
        raise ValueError("invalid_dataset_manifest")
    # Evaluation metadata is owned exclusively by evaluation; never retained in
    # the production projection, config snapshot, prompt, or registry digest.
    production = {k: v for k, v in document.items() if k != "evaluation"}
    registry = DatasetManifest.model_validate(production)
    if registry.dataset_id != dataset_id or registry.dataset_version < 1 or registry.default_scene not in registry.scenes:
        raise ValueError("invalid_dataset_manifest")
    if set(registry.source_profiles) != {"aminer", "wazuh"}:
        raise ValueError("unsupported_registry_sources")
    namespaces, paths = set(), set()
    for scene_id, scene in registry.scenes.items():
        identifier(scene_id)
        if not scene.namespace or not scene.network_namespace or set(scene.raw) != set(registry.source_profiles):
            raise ValueError("invalid_scene_manifest")
        for source, path in scene.raw.items():
            resolved = security_path(root, base, path)
            if PurePosixPath(path).parts[:2] != (scene_id, "raw"):
                raise ValueError("raw_path_scene_mismatch")
            namespace = scene.namespace + "." + source
            if namespace in namespaces or resolved in paths:
                raise ValueError("duplicate_scene_source_identity")
            namespaces.add(namespace)
            paths.add(resolved)
    if len({s.network_namespace for s in registry.scenes.values()}) != len(registry.scenes):
        raise ValueError("duplicate_scene_network_namespace")
    return registry


@dataclass(frozen=True)
class LoadedDataset:
    dataset_id: str
    scene_id: str
    name: str
    config: object
    sources: dict
    inputs: list
    metadata: dict
    source_contexts: dict
    missing_files: tuple

    @property
    def status(self):
        return "missing_raw_data" if self.missing_files else "files_present_unvalidated"

    @property
    def request(self):
        return {"config_version": self.config.algorithm.version, "inputs": self.inputs}


def load_dataset(root, dataset_id="ait_ads", scene_id=None, *, config_version="v0"):
    root = Path(root).resolve()
    registry = read_registry(root, dataset_id)
    scene_id = identifier(scene_id or registry.default_scene)
    if scene_id not in registry.scenes:
        raise ValueError("unknown_scene")
    scene = registry.scenes[scene_id]
    if not scene.enabled:
        raise ValueError("scene_disabled")
    if config_version not in {"v0", "v2", "v3", "v4"}:
        raise ValueError("unknown_config_version")
    config = load_config(root / f"configs/algorithm-{config_version}.yaml", deployment_override=root / "configs/sources.yaml")
    sources, inputs, timezones = {}, [], {}
    for source, profile in sorted(registry.source_profiles.items()):
        namespace = scene.namespace + "." + source
        setting = AdapterSettings(source_namespace=namespace, format_profile=profile.format_profile,
            generator=profile.generator, generator_version=profile.generator_version,
            dataset_version=registry.dataset_version, epoch_unit=profile.epoch_unit,
            network_namespace=scene.network_namespace)
        sources[namespace] = (source, setting)
        timezones[namespace] = profile.timezone
        inputs.append({"source": source, "source_ref": namespace,
                       "path": security_path(root, root / "data" / dataset_id, scene.raw[source])})
    snapshot = config.snapshot
    snapshot["normalization"]["source_timezones"] = timezones
    config = restore_config(snapshot)
    metadata = {"dataset_id": dataset_id, "scene_id": scene_id, "dataset_version": registry.dataset_version,
                "default_scene": registry.default_scene,
                "sources": {i["source_ref"]: i["path"] for i in inputs}}
    metadata["registry_selection_digest"] = content_digest(metadata)
    contexts = {i["source_ref"]: {"dataset_id": dataset_id, "scene_id": scene_id, "path": i["path"]} for i in inputs}
    return LoadedDataset(dataset_id, scene_id, registry.name, config, sources, inputs, metadata, contexts,
                         tuple(i["path"] for i in inputs if not (root / i["path"]).is_file()))


def source_contexts(root):
    """Resolve all registered refs for ingress guards, without reading raw data."""
    root = Path(root).resolve()
    manifest = root / "data/ait_ads/dataset.yaml"
    if not manifest.is_file():
        return {}
    registry = read_registry(root)
    return {scene.namespace + "." + source:
            {"dataset_id": registry.dataset_id, "scene_id": sid,
             "path": security_path(root, manifest.parent, path), "enabled": scene.enabled}
            for sid, scene in registry.scenes.items() for source, path in scene.raw.items()}

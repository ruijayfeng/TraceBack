"""Bounded CPTC gzip/Splunk reader and explicitly declared ingestion sources.

EVE remains the unmodified raw_alert root. Export wrappers and ordinal locators
travel separately as provenance, never as device IDs or algorithm evidence.
"""
from dataclasses import dataclass
import gzip
import json
from pathlib import Path, PurePosixPath
import re

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr
import yaml

from app.config import _UniqueKeyLoader, load_config
from app.utils.stable_id import content_digest
from .base import AdapterSettings, reject_truth
from .suricata import SuricataAdapter


def strict_json(value):
    def constant(_):
        raise ValueError("non_finite_json_number")
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)


def json_array_items(handle, *, chunk_size=65536, max_record_chars=8 * 1024 * 1024):
    """One bounded array item at a time; syntax damage aborts the file explicitly."""
    buffer, eof = "", False
    decoder = json.JSONDecoder()
    def fill():
        nonlocal buffer, eof
        part = handle.read(chunk_size)
        eof = not part
        buffer += part
    fill()
    buffer = buffer.lstrip("\ufeff \r\n\t")
    while not buffer and not eof:
        fill()
        buffer = buffer.lstrip()
    if not buffer.startswith("["):
        raise ValueError("outer_json_not_array")
    buffer = buffer[1:]
    expect_item, seen = True, False
    while True:
        buffer = buffer.lstrip()
        if not buffer and not eof:
            fill()
            continue
        if buffer.startswith("]"):
            if expect_item and seen:
                raise ValueError("outer_json_trailing_comma")
            buffer = buffer[1:]
            while True:
                if buffer.strip():
                    raise ValueError("outer_json_trailing_content")
                if eof:
                    return
                buffer = ""
                fill()  # Read through EOF, including gzip CRC/trailer validation.
        if not expect_item:
            if not buffer.startswith(","):
                raise ValueError("outer_json_missing_comma_or_close")
            buffer, expect_item = buffer[1:], True
            continue
        try:
            _, end = decoder.raw_decode(buffer)
        except ValueError as exc:
            if eof:
                raise ValueError("outer_json_malformed") from exc
            if len(buffer) > max_record_chars:
                raise ValueError("record_size_limit") from exc
            fill()
            continue
        if end > max_record_chars:
            raise ValueError("record_size_limit")
        if not eof and (end == len(buffer) or buffer[end] not in ",] \r\n\t"):
            if len(buffer) > max_record_chars:
                raise ValueError("record_size_limit")
            fill()
            continue
        yield buffer[:end]
        buffer, expect_item, seen = buffer[end:], False, True


def unwrap_splunk(wrapper):
    if type(wrapper) is not dict or not wrapper:
        raise ValueError("invalid_splunk_object")
    reject_truth(wrapper)
    if "_raw" not in wrapper:
        raise ValueError("missing_raw")
    if type(wrapper["_raw"]) is not str:
        raise ValueError("raw_not_json_string")
    try:
        eve = strict_json(wrapper["_raw"])
    except ValueError as exc:
        raise ValueError("raw_json_malformed") from exc
    if type(eve) is not dict or not eve:
        raise ValueError("invalid_eve_object")
    reject_truth(eve)
    return eve


@dataclass(frozen=True)
class CPTCRecord:
    ordinal: int
    wrapper: dict | None = None
    eve: dict | None = None
    error: str | None = None


def read_cptc_file(path, **limits):
    path = Path(path).resolve()
    if not path.name.endswith(".json.gz") or "evaluation" in {p.lower() for p in path.parts}:
        raise ValueError("input_path_not_security_alert")
    with gzip.open(path, "rt", encoding="utf-8-sig") as handle:
        for ordinal, value in enumerate(json_array_items(handle, **limits), 1):
            try:
                wrapper = strict_json(value)
                eve = unwrap_splunk(wrapper)
            except (ValueError, TypeError) as exc:
                # Contaminated wrappers are never forwarded or stored in diagnostics.
                yield CPTCRecord(ordinal, error=str(exc))
            else:
                yield CPTCRecord(ordinal, wrapper, eve)


class ManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Partition(ManifestModel):
    file: StrictStr
    expected_records: StrictInt


class CPTCManifest(ManifestModel):
    dataset_id: StrictStr
    dataset_version: StrictInt
    source_type: StrictStr
    source_namespace: StrictStr
    network_namespace: StrictStr
    timezone: StrictStr
    format_profile: StrictStr
    generator: StrictStr
    generator_version: StrictStr
    mapping_override: StrictStr
    partitions: dict[StrictStr, Partition]


@dataclass(frozen=True)
class CPTCDataset:
    root: Path
    manifest: CPTCManifest
    config: object
    adapters: dict
    paths: dict

    @property
    def source_settings(self):
        return {a.settings.source_namespace: a.settings for a in self.adapters.values()}

    @property
    def snapshot(self):
        return {"algorithm": self.config.snapshot,
                "sources": {k: s.snapshot() for k, s in sorted(self.source_settings.items())},
                "dataset": self.manifest.model_dump()}

    @property
    def config_hash(self):
        return content_digest(self.snapshot)


def declared_path(root, reference, base):
    relative = PurePosixPath(reference)
    if (not reference or "\\" in reference or ":" in reference or "%" in reference
            or relative.is_absolute() or any(p in {"", ".", "..", "evaluation"} for p in reference.lower().split("/"))):
        raise ValueError("invalid_cptc_declared_path")
    path = root / reference
    if not path.resolve().is_relative_to((root / base).resolve()) or path.resolve() != path.absolute():
        raise ValueError("redirected_cptc_declared_path")
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)):
        raise ValueError("redirected_cptc_declared_path")
    return path


def load_cptc_dataset(root):
    root = Path(root).resolve()
    path = declared_path(root, "data/cptc_2018/dataset.yaml", "data/cptc_2018")
    with path.open(encoding="utf-8") as handle:
        manifest = CPTCManifest.model_validate(yaml.load(handle, Loader=_UniqueKeyLoader))
    if (manifest.dataset_id != "cptc_2018" or manifest.dataset_version < 1
            or manifest.source_type != "suricata" or manifest.timezone != "UTC"
            or not manifest.source_namespace or not manifest.network_namespace or not manifest.partitions):
        raise ValueError("invalid_cptc_manifest")
    override = declared_path(root, manifest.mapping_override, "configs")
    config = load_config(root / "configs/algorithm-v0.yaml", deployment_override=override)
    from app.services.storage import restore_config
    snapshot = config.snapshot
    snapshot["normalization"]["source_timezones"] = {
        manifest.source_namespace + "." + p: manifest.timezone for p in manifest.partitions}
    config = restore_config(snapshot)
    adapters, paths = {}, {}
    for partition, entry in sorted(manifest.partitions.items()):
        if not re.fullmatch(r"[a-z][a-z0-9_]*", partition) or entry.expected_records < 0:
            raise ValueError("invalid_cptc_partition")
        path = declared_path(root, "data/cptc_2018/" + entry.file, "data/cptc_2018/raw/suricata")
        if not path.name.endswith(".json.gz") or path in paths.values():
            raise ValueError("invalid_cptc_partition_file")
        paths[partition] = path
        adapters[partition] = SuricataAdapter(config, AdapterSettings(
            source_namespace=manifest.source_namespace + "." + partition,
            format_profile=manifest.format_profile, generator=manifest.generator,
            generator_version=manifest.generator_version, dataset_version=manifest.dataset_version,
            network_namespace=manifest.network_namespace))
    return CPTCDataset(root, manifest, config, adapters, paths)

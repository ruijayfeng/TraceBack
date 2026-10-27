"""Official ①–④ boundary: Canonical -> Entity/Binding -> Noise -> Behavior.

load_alert_pipeline is the official file entry. Compatibility callers with
CanonicalAlerts use prepare_alerts, the same Noise -> Behavior boundary.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path

from app.adapters.base import AdapterSettings
from app.adapters.multisource import MultiSourceAdapter
from app.config import load_config, read_yaml
from app.noise_filter import filter_alerts
from app.noise_filter.models import NoiseFilterResult
from app.stages.models import BehaviorAnnotation
from app.stages.behavior import normalize_behavior
from app.stages.config import load_stage_config
from app.services.pipeline_progress import notify

ROOT = Path(__file__).resolve().parents[3]
OFFICIAL_PIPELINE_ENTRY = 'app.services.alert_pipeline.load_alert_pipeline'


@dataclass
class NormalizedAlerts:
    noise_filter: NoiseFilterResult
    behaviors: list[BehaviorAnnotation]
    behavior_config_hash: str
    source_settings: dict
    entities: list | None = None
    identity_projection: object = None
    identity_archive_entities: list = field(default_factory=list, repr=False)

    @property
    def alerts(self):
        return self.noise_filter.kept_alerts

    def validate_handoff(self):
        if self.identity_projection is not None:
            # Alias evidence remains addressable in the complete pre-noise archive.
            self.identity_projection.validate_trace(self.noise_filter.original_alerts,
                self.identity_archive_entities or self.entities or [])
        ids = [a.alert_id for a in self.alerts]
        if (len(set(ids)) != len(ids) or sorted(b.alert_id for b in self.behaviors) != sorted(ids)
                or any(b.community_id is not None for b in self.behaviors)):
            raise ValueError('normalized_alert_behavior_partition_mismatch')
        context = {'alerts': {a.alert_id: a for a in self.alerts}}
        for annotation in self.behaviors:
            BehaviorAnnotation.model_validate(annotation.model_dump(), context=context)
        if self.entities is not None:
            entity_map = {e.entity_id: e for e in self.entities}
            expected = {eid for a in self.alerts for eid in a.entity_ids}
            if (len(entity_map) != len(self.entities) or set(entity_map) != expected
                    or any(a.extraction_version != 'front-data-v1' for a in self.alerts)
                    or any(set(e.alert_ids) != {a.alert_id for a in self.alerts if e.entity_id in a.entity_ids}
                           for e in self.entities)):
                raise ValueError('normalized_entity_partition_mismatch')


def normalize_behaviors(alerts, config, resolver=None):
    return [normalize_behavior(a, config, resolver) for a in sorted(alerts, key=lambda a: a.alert_id)]


def prepare_alerts(alerts, *, behavior_config=None, noise_config=None, resolver=None, source_settings=None,
                   entities=None, identity_projection=None, progress=None):
    policy = behavior_config or load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    notify(progress, 3, 'RUNNING')
    noise = filter_alerts(alerts, noise_config)
    notify(progress, 3, 'COMPLETED')
    kept_ids = {a.alert_id for a in noise.kept_alerts}
    kept_entities = None if entities is None else [e.model_copy(update=dict(alert_ids=sorted(
        set(e.alert_ids) & kept_ids))) for e in entities if set(e.alert_ids) & kept_ids]
    notify(progress, 4, 'RUNNING')
    result = NormalizedAlerts(noise, normalize_behaviors(noise.kept_alerts, policy, resolver),
                              policy.digest, source_settings or {}, kept_entities, identity_projection, entities or [])
    result.validate_handoff()
    notify(progress, 4, 'COMPLETED')
    return result


def ingest_records(records, adapters, *, behavior_config=None, noise_config=None, resolver=None, progress=None):
    from app.entities.extraction import extract_entities
    def canonical():
        for record in records:
            yield adapters[record['source_type']].convert_record(record)
    settings = {a.settings.source_namespace: a.settings for a in adapters.values()}
    notify(progress, 1, 'RUNNING')
    alerts = list(canonical())
    notify(progress, 1, 'COMPLETED')
    notify(progress, 2, 'RUNNING')
    extracted = extract_entities(alerts, settings, contract='front-data-v1')
    notify(progress, 2, 'COMPLETED')
    return prepare_alerts(extracted.alerts, behavior_config=behavior_config, noise_config=noise_config,
                          resolver=resolver, source_settings=settings, entities=extracted.entities,
                          identity_projection=extracted.identity_projection, progress=progress)


def native_alert_adapters():
    """The single native ingress registry shared by CLI and upload validation."""
    config = load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',
                         deployment_override=ROOT/'configs/front-data-sources.yaml')
    routing = read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
    return {s: MultiSourceAdapter(config, AdapterSettings(**v), s) for s,v in routing.items()}


def load_alert_pipeline(input_path, *, behavior_config=None, noise_config=None, resolver=None, progress=None):
    """Read native JSONL; reject contaminated input, never read labels or publish snapshots."""
    input_path = Path(input_path).resolve()
    if any(p.casefold() in {'ground_truth', 'evaluation', 'protected', 'validated'} for p in input_path.parts):
        raise ValueError('input_must_be_unannotated_security_alerts')
    adapters = native_alert_adapters()
    with input_path.open(encoding='utf-8-sig') as stream:
        result = ingest_records((json.loads(line) for line in stream if line.strip()), adapters,
            behavior_config=behavior_config, noise_config=noise_config, resolver=resolver, progress=progress)
    return result

"""NOT_OFFICIAL_ANALYSIS_PIPELINE: offline projection/index diagnostics only.

This preserves historical inspection semantics (all supplied CanonicalAlerts).
Official analysis starts at app.services.alert_pipeline.load_alert_pipeline.
"""
from collections import Counter
from dataclasses import dataclass

from app.correlation.candidates import generate_candidates
from app.correlation.index import AlertIndex
from app.entities.extraction import extract_entities

PIPELINE_ROLE = 'NOT_OFFICIAL_ANALYSIS_PIPELINE'


@dataclass
class FrontDataResult:
    index: AlertIndex
    candidates: object
    summary: dict


def prepare_front_data(records, adapters, config):
    """Records are native alert envelopes; wrapper locators never enter identity."""
    alerts, counts = [], Counter()
    for record in records:
        source = record['source_type']
        alert = adapters[source].convert_record(record)
        alerts.append(alert)
        counts[source] += 1
    return index_front_data(alerts, {a.settings.source_namespace: a.settings for a in adapters.values()},
                            config, counts=counts)


def index_front_data(alerts, settings, config, *, groups=(), counts=None):
    """Also accepts old sparse CanonicalAlerts; supplied dedupe groups are retained."""
    # Older stored CanonicalAlerts may predate adapter context projection.
    from app.entities.context import project_candidates
    projected = []
    for alert in alerts:
        data = alert.model_dump()
        data['context_candidates'] = project_candidates(alert.raw_alert, settings[alert.source_namespace])
        projected.append(type(alert).model_validate(data))
    result = extract_entities(projected, settings, contract='front-data-v1')
    index = AlertIndex(result.alerts, groups, result.entities)
    candidates = generate_candidates(index, config)
    n = len(index.alerts)
    theoretical = n * (n - 1) // 2
    context_counts = Counter(c.kind for a in result.alerts for c in a.contexts)
    entity_counts = Counter(e.type.value.lower() for e in result.entities)
    key_counts = Counter(r.kind for r in index.context_refs.values())
    key_counts.update(entity_counts)
    summary = dict(contract_version='front-data-v1', pipeline_role=PIPELINE_ROLE, total_alerts=n,
        input_alerts=sum(counts.values()) if counts is not None else len(projected),
        duplicate_imports=(sum(counts.values()) if counts is not None else len(projected))-n,
        by_source=dict(sorted((counts or Counter(a.source_type.value for a in result.alerts)).items())),
        context_counts={kind: context_counts[kind] for kind in ('request','flow','session','task')},
        entity_counts={kind: entity_counts[kind] for kind in ('host','account','process','ip')},
        index_keys={kind: key_counts[kind] for kind in ('request','flow','session','task','host','account','process','ip')},
        candidate_count=len(candidates.pairs), global_alert_pair_count=theoretical,
        candidate_reduction_ratio=1-len(candidates.pairs)/theoretical if theoretical else None,
        examined_neighbors=candidates.examined_neighbors,
        potential_pair_stats=candidates.potential_pair_stats,
        candidate_admission_stats=candidates.candidate_admission_stats,
        candidate_truncated=candidates.candidate_truncated,
        candidate_channels=dict(sorted(Counter(ch for p in candidates.pairs for ch in p.channels).items())))
    return FrontDataResult(index, candidates, summary)

"""Mapping first; bounded, evidence-bound semantic fallback on one alert only."""
from pydantic import ValidationError

from app.adapters.base import reject_truth
from app.models.alerts import EvidencePointer
from app.models.base import resolve_pointer
from app.utils.stable_id import content_digest
from .models import BehaviorAnnotation, SemanticAnswer, VOCABULARY


def semantic_input(alert, config):
    reject_truth(alert.raw_alert)
    fields, refs = {}, {}
    values = dict(source_type=alert.source_type.value, category=alert.category.value,
        alert_type=alert.alert_type, signature=alert.signature, src_ip=alert.src_ip,
        dst_ip=alert.dst_ip, src_port=alert.src_port, dst_port=alert.dst_port,
        command=alert.command, file=alert.file, url=alert.url)
    if alert.process:
        values.update(process_name=alert.process.name, executable=alert.process.executable)
    for name, value in values.items():
        parent = 'process' if name in ('process_name', 'executable') else name
        provenance = alert.field_provenance.get(parent)
        if value is None or provenance is None:
            continue
        # Reject oversize fields instead of silently changing their meaning.
        if isinstance(value, str) and len(value) > config.semantic_max_field_chars:
            continue
        raw_value = resolve_pointer(alert.raw_alert, provenance.raw_pointer)
        if name in ('process_name', 'executable') and raw_value != value:
            # A ProcessRef's root provenance can point to the PID field. Do not
            # present that pointer as evidence for a different name/executable.
            continue
        fields[name] = value
        refs[name] = provenance.raw_pointer
    for name, candidates in dict(action=['native.action'], protocol=['native.protocol', 'native.proto']).items():
        found = []
        for key in candidates:
            provenance = alert.field_provenance.get(key)
            if provenance:
                value = resolve_pointer(alert.raw_alert, provenance.raw_pointer)
                if type(value) is str and value.strip() and len(value) <= config.semantic_max_field_chars:
                    found.append((value, provenance.raw_pointer))
        if found and len({v.casefold() for v, _ in found}) == 1:
            fields[name], refs[name] = found[0]
    # Raw alert, wrapper IDs, payloads, other alerts and rejected candidates are
    # deliberately absent. The resolver cannot return entities or membership.
    evidence = [EvidencePointer(alert_id=alert.alert_id, pointer=p, side='shared') for p in sorted(set(refs.values()))]
    payload = dict(version=config.version, vocabulary=VOCABULARY, fields=fields,
                   evidence=[p.model_dump(mode='json') for p in evidence])
    return fields, refs, evidence, payload


def normalize_behavior(alert, community_id, config, resolver=None):
    fields, refs, evidence, payload = semantic_input(alert, config)
    digest = content_digest(payload)
    matches = []
    for rule in config.rules:
        if all((condition.field in fields if condition.op == 'exists' else
                isinstance(fields.get(condition.field), str) and
                fields[condition.field].casefold() in {v.casefold() for v in condition.values})
               for condition in rule.all):
            matches.append(rule)
    args = dict(alert_id=alert.alert_id, community_id=community_id,
                input_digest=digest, evidence=evidence)
    if len({r.behavior for r in matches}) == 1:
        used = {c.field for r in matches for c in r.all}
        args['evidence'] = [p for p in evidence if p.pointer in {refs[f] for f in used}]
        return BehaviorAnnotation(**args, behavior=matches[0].behavior, resolver='mapping',
            matched_rule=[r.id for r in matches], confidence=min(r.confidence for r in matches),
            reason='Observed fields match versioned rules: ' + ', '.join(r.id for r in matches))
    fallback_reason = 'mapping_conflict' if matches else 'mapping_no_reliable_match'
    if resolver is None:
        return BehaviorAnnotation(**args, behavior='UNKNOWN', resolver='unknown',
            matched_rule=[], confidence=0.0, reason=fallback_reason + ':provider_not_configured')
    try:
        # JSON round-trip isolates the provider from the input object.
        from app.utils.stable_id import canonical_json
        import json
        response = resolver.resolve(json.loads(canonical_json(payload)))
        answer = SemanticAnswer.model_validate_json(response) if isinstance(response, str) else SemanticAnswer.model_validate(response)
    except (ValidationError, ValueError, TypeError):
        return BehaviorAnnotation(**args, behavior='UNKNOWN', resolver='unknown',
            matched_rule=[], confidence=0.0, reason=fallback_reason + ':invalid_semantic_response')
    except Exception:
        # Never expose provider exception strings, credentials or raw responses.
        return BehaviorAnnotation(**args, behavior='UNKNOWN', resolver='unknown',
            matched_rule=[], confidence=0.0, reason=fallback_reason + ':semantic_provider_failed')
    known = answer.behavior != 'UNKNOWN' and answer.confidence >= config.ai_confidence_threshold
    return BehaviorAnnotation(**args, behavior=answer.behavior if known else 'UNKNOWN',
        resolver='ai', matched_rule=[], confidence=answer.confidence,
        reason=fallback_reason + (':accepted_ai_annotation:' if known else ':ai_abstained_or_below_threshold:') + answer.reasoning)

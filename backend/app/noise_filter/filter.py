"""Conservative deterministic filtering before any entity/context binding."""
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, time, timedelta, timezone

from pydantic import ValidationError

from app.adapters.base import reject_truth
from app.models import CanonicalAlert
from app.utils.stable_id import content_digest
from .config import load_noise_config
from .models import NoiseAuditRecord, NoiseFilterResult, NoiseReason


def _seconds(alert):
    return datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00')).timestamp()


def _remove_pointer(raw, pointer):
    """Remove only an attested timestamp; preserve all IDs, actions and context."""
    parts = [p.replace('~1', '/').replace('~0', '~') for p in pointer.split('/')[1:]]
    if not parts:
        return False
    node = raw
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    if isinstance(node, dict):
        node.pop(parts[-1], None)
        return True
    return False


def _duplicate_key(alert):
    # Rule + a concrete object + identical remaining raw payload. A signature
    # and IP/time coincidence alone can never erase distinct native events.
    if not (alert.rule_id or alert.signature or alert.alert_type):
        return None
    if not (alert.host or alert.src_ip and alert.dst_ip or alert.process or alert.file or alert.url):
        return None
    raw = deepcopy(alert.raw_alert)
    if not isinstance(raw, dict) or not _remove_pointer(raw, alert.field_provenance['timestamp'].raw_pointer):
        return None
    return content_digest(dict(source_type=alert.source_type.value,
        source_namespace=alert.source_namespace, sensor=alert.sensor,
        rule_id=alert.rule_id, signature=alert.signature, alert_type=alert.alert_type,
        host=alert.host, src_ip=alert.src_ip, dst_ip=alert.dst_ip, src_port=alert.src_port,
        dst_port=alert.dst_port, process=alert.process.model_dump() if alert.process else None,
        payload=raw))


def _matches(alert, rule):
    matched = {}
    for field, expected in rule.match.items():
        if field == 'process':
            values = [alert.process.name, alert.process.executable, alert.process.guid] if alert.process else []
        elif field == 'path':
            values = [alert.file, alert.url]
        else:
            value = getattr(alert, field)
            values = [value.value if hasattr(value, 'value') else value]
        if expected not in values:
            return None
        matched[field] = expected
    if rule.time_pattern:
        pattern = rule.time_pattern
        dt = datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00')).astimezone(timezone.utc)
        start, end = time.fromisoformat(pattern.start), time.fromisoformat(pattern.end)
        clock = dt.time()
        # Weekday denotes the start day for an overnight interval.
        day = dt - timedelta(days=1) if start > end and clock <= end else dt
        if day.weekday() not in pattern.weekdays or not (
                start <= clock <= end if start <= end else clock >= start or clock <= end):
            return None
        matched['time_pattern'] = pattern.model_dump(mode='json')
        matched['timestamp'] = alert.timestamp
    return matched


def filter_alerts(alerts, config=None):
    config = config if config is not None else load_noise_config()
    originals = list(alerts)
    decisions, buckets, identities = {}, defaultdict(list), {}
    for i, alert in enumerate(originals):
        reject_truth(alert.raw_alert)
        # Revalidate even model_copy/model_construct objects. Missing ordinary
        # fields and UNKNOWN category/type remain valid under the real contract.
        try:
            CanonicalAlert.model_validate(alert.model_dump())
        except ValidationError as exc:
            decisions[i] = dict(keep=False, reason_code=NoiseReason.INVALID_FOR_RECONSTRUCTION,
                rule_id='builtin:canonical-contract-v1', evidence=dict(errors=[
                    dict(location=list(e['loc']), type=e['type']) for e in exc.errors()]))
            continue
        if alert.alert_id in identities and identities[alert.alert_id] != alert.canonical_json():
            raise ValueError('same_alert_id_with_conflicting_content')
        identities[alert.alert_id] = alert.canonical_json()
        for rule in config.background_rules:
            matched = _matches(alert, rule)
            if matched is not None:
                decisions[i] = dict(keep=False, reason_code=NoiseReason.KNOWN_BACKGROUND_NOISE,
                    rule_id=rule.rule_id, evidence=dict(matched_fields=matched))
                break
        else:
            key = _duplicate_key(alert)
            # Exact repeated imports are unambiguous even for sparse alerts.
            buckets[key or 'identity:' + alert.alert_id].append(i)

    for key, indices in buckets.items():
        ordered = sorted(indices, key=lambda i: (_seconds(originals[i]), originals[i].alert_id, i))
        clusters = []
        for i in ordered:
            if not clusters or _seconds(originals[i]) - _seconds(originals[clusters[-1][0]]) > config.duplicate_window_seconds:
                clusters.append([])
            clusters[-1].append(i)
        for group in clusters:
            representative = originals[group[0]].alert_id
            group_data = dict(representative_alert_id=representative,
                duplicate_group_id='noise_dup_' + content_digest(dict(key=key,
                    members=sorted(originals[i].alert_id for i in group))), duplicate_count=len(group)) if len(group) > 1 else {}
            for position, i in enumerate(group):
                decisions[i] = dict(keep=position == 0,
                    reason_code=NoiseReason.KEEP if position == 0 else NoiseReason.DUPLICATE_NOISE,
                    rule_id=None if position == 0 else 'builtin:exact-observation-v1',
                    evidence=dict(window_seconds=config.duplicate_window_seconds,
                        payload_digest=key, timestamp=originals[i].timestamp,
                        representative_timestamp=originals[group[0]].timestamp,
                        timestamp_raw_pointer=originals[i].field_provenance['timestamp'].raw_pointer,
                        equality_basis=('identical_canonical_identity' if key.startswith('identity:') else
                            'same_source_rule_object_and_full_raw_except_attested_timestamp'),
                        native_ids_preserved=True) if len(group) > 1 else {}, **group_data)
    audits = [NoiseAuditRecord(input_index=i, alert_id=a.alert_id, raw_fingerprint=a.raw_fingerprint,
        raw_evidence_ref=f'noise_source_alerts.jsonl.gz#/records/{i}/raw_alert', **decisions[i])
        for i, a in enumerate(originals)]
    kept = sorted([a for a, audit in zip(originals, audits) if audit.keep], key=lambda a:a.alert_id)
    counts = Counter(a.reason_code for a in audits if not a.keep)
    statistics = dict(INPUT_ALERTS=len(originals), KEPT_ALERTS=len(kept), REMOVED_ALERTS=len(originals)-len(kept),
        NOISE_REDUCTION_RATE=(len(originals)-len(kept))/len(originals) if originals else 0.0,
        DUPLICATE_NOISE_COUNT=counts[NoiseReason.DUPLICATE_NOISE],
        KNOWN_BACKGROUND_NOISE_COUNT=counts[NoiseReason.KNOWN_BACKGROUND_NOISE],
        INVALID_NOISE_COUNT=counts[NoiseReason.INVALID_FOR_RECONSTRUCTION])
    return NoiseFilterResult(originals, kept, audits, statistics, config.model_dump(mode='json'), config.digest)

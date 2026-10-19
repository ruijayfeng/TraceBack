"""Conservative identity of an embedded alert observation; no log parsing."""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import unicodedata

from app.models.base import resolve_pointer
from app.utils.stable_id import content_digest, canonical_json, utc_text


@dataclass(frozen=True)
class ObservationIdentity:
    message_fingerprint: str | None
    pointers: tuple[str, ...]
    event_fingerprint: str | None
    observation_id: str
    protocol: str | None
    event_pointers: tuple[str, ...]


class ObservationMatcher:
    def __init__(self, alerts, config, metadata, settings):
        self.config, self.metadata = config, metadata
        from app.services.capacity import execution_state, DiskScalarObjects
        state = execution_state()
        self.identities = DiskScalarObjects(state.database(), 'observation_identities') if state else {}
        for aid, alert in alerts.items():
            messages = []
            for pointer in config.message_pointers.get(alert.source_type.value, []):
                try:
                    value = resolve_pointer(alert.raw_alert, pointer)
                except (ValueError, KeyError, IndexError, TypeError):
                    continue
                # A single embedded message is comparable. Aggregate alerts
                # with several snippets cannot be equated by selecting a line.
                if isinstance(value, list) and len(value) == 1:
                    value = value[0]
                if isinstance(value, str) and value.strip():
                    messages.append((pointer, unicodedata.normalize('NFC', value.strip())))
            # Multiple disagreeing message fields do not select an arbitrary winner.
            values = {v for _, v in messages}
            fingerprint = content_digest(next(iter(values))) if len(values) == 1 else None
            fields, event_refs = {}, []
            for field, pointers in config.event_pointers.get(alert.source_type.value, {}).items():
                values = set()
                for pointer in pointers:
                    try:
                        value = resolve_pointer(alert.raw_alert, pointer)
                    except (ValueError, KeyError, IndexError, TypeError):
                        continue
                    if type(value) not in (str, int) or str(value).strip() == '':
                        continue
                    value = str(value).strip()
                    if field in ('flow_id', 'transaction_id'):
                        try:
                            number = Decimal(value)
                            if number.is_finite() and number == number.to_integral_value():
                                value = str(int(number))
                        except InvalidOperation:
                            pass
                    elif field == 'protocol':
                        value = value.upper()
                    elif field == 'event_time':
                        try:
                            value = utc_text(value)
                        except ValueError:
                            continue
                    values.add(value)
                    event_refs.append(pointer)
                fields[field] = next(iter(values)) if len(values) == 1 else None
            source = settings[alert.source_namespace]
            network_tuple = [getattr(alert, n) for n in ('src_ip', 'src_port', 'dst_ip', 'dst_port')]
            event = None
            if fields.get('flow_id') and fields.get('protocol') and all(v is not None for v in network_tuple):
                # One flow can carry many requests. Without a transaction ID,
                # only an exact event timestamp identifies a repeated detection.
                event = content_digest(dict(scope=source.network_namespace or alert.source_namespace,
                    flow_id=fields['flow_id'], protocol=fields['protocol'], network_tuple=network_tuple,
                    transaction_id=fields.get('transaction_id'),
                    event_time=None if fields.get('transaction_id') is not None else fields.get('event_time') or alert.timestamp))
            identity = content_digest(dict(event=event, message=fingerprint if not event else None,
                scope=[list(t) for t in sorted(metadata[aid]['targets'])] if not event else None,
                timestamp=None if event else fields.get('event_time') or alert.timestamp,
                unresolved_raw=None if event or fingerprint else [alert.source_namespace, alert.raw_fingerprint]))
            self.identities[aid] = ObservationIdentity(fingerprint, tuple(p for p, _ in messages),
                event, 'obs_' + identity, fields.get('protocol'), tuple(sorted(set(event_refs))))

    def bucket_keys(self, aid):
        identity = self.identities[aid]
        if identity.message_fingerprint:
            for target in sorted(self.metadata[aid]['targets']):
                yield ('message', identity.message_fingerprint, target)
        if identity.event_fingerprint:
            yield ('network_event', identity.event_fingerprint)

    def compare(self, a, b):
        x, y = self.identities[a.alert_id], self.identities[b.alert_id]
        ma, mb = self.metadata[a.alert_id], self.metadata[b.alert_id]
        gap = abs((ma['time'] - mb['time']).total_seconds())
        constraints = []
        for name in ('account', 'session', 'file', 'command', 'url'):
            if getattr(a, name) is not None and getattr(a, name) == getattr(b, name):
                constraints.append(name)
        if all(getattr(a, n) is not None and getattr(a, n) == getattr(b, n)
               for n in ('src_ip', 'dst_ip', 'src_port', 'dst_port')):
            constraints.append('network_tuple')
        if (a.process and b.process and a.process.pid is not None and a.process.start_time is not None
                and a.process == b.process):
            constraints.append('process_instance')
        incompatible = any(getattr(a, name) is not None and getattr(b, name) is not None
                           and canonical_json(getattr(a, name).model_dump() if hasattr(getattr(a, name), 'model_dump') else getattr(a, name))
                           != canonical_json(getattr(b, name).model_dump() if hasattr(getattr(b, name), 'model_dump') else getattr(b, name))
                           for name in ('host', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'account',
                                        'session', 'process', 'parent_process', 'url', 'file', 'command'))
        same_event = bool(x.event_fingerprint and x.event_fingerprint == y.event_fingerprint)
        same_message = bool(x.message_fingerprint and x.message_fingerprint == y.message_fingerprint
            and ma['targets'] & mb['targets'] and gap <= self.config.window_seconds
            and len(constraints) >= self.config.minimum_context_matches and not incompatible
            and not (x.event_fingerprint and y.event_fingerprint and x.event_fingerprint != y.event_fingerprint))
        equivalent = (same_event or same_message) and gap <= self.config.window_seconds and not incompatible
        return dict(equivalent=equivalent, gap_seconds=gap, constraints=sorted(constraints),
            message_fingerprint=x.message_fingerprint if x.message_fingerprint == y.message_fingerprint else None,
            target_match=bool(ma['targets'] & mb['targets']), incompatible=incompatible,
            identity_basis='network_event' if same_event else 'embedded_message' if same_message else 'unresolved',
            observation_ids=sorted({x.observation_id, y.observation_id}),
            evidence_refs=[dict(alert_id=alert.alert_id, pointer=p, side=side)
                for alert, identity, side in ((a, x, 'src'), (b, y, 'dst'))
                for p in sorted(set(identity.pointers + identity.event_pointers))])

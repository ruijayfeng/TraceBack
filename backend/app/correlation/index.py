"""Immutable fact-group, time and scoped-entity indexes.

Internal postings keep original members: a nonrepresentative can retrieve a
candidate and can later win scoring. Frequency is always counted per fact group.
"""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime
import math
import zlib


class PostingRuns(Mapping):
    """Recover exactly the timestamp tie group without resident nested tuples."""
    def __init__(self, posting):
        self.posting = posting

    def __getitem__(self, stamp):
        p = self.posting
        lo, hi = p.bounds(stamp, stamp)
        if lo == hi:
            raise KeyError(stamp)
        groups = defaultdict(list)
        for aid in p.members[lo:hi]:
            groups[p.index.owner[aid]].append(aid)
        return sorted((rep, tuple(sorted(aids))) for rep, aids in groups.items())

    def __iter__(self):
        return iter(dict.fromkeys(self.posting.times))

    def __len__(self):
        return len(set(self.posting.times))

from app.adapters.base import reject_truth
from app.models import CanonicalAlert, DedupeGroup, Entity
from app.models.base import resolve_pointer
from app.utils.stable_id import id_for


def event_microseconds(alert):
    from app.utils.stable_id import utc_text
    stamp = utc_text(alert) if isinstance(alert, str) else alert.timestamp
    dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    epoch = datetime.fromisoformat("1970-01-01T00:00:00+00:00")
    delta = dt - epoch
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


class TemporalPosting:
    """Range count/union by blocked bitsets; enumerate only nearest retained hits.

    Block size is an internal indexing choice, never an algorithm budget. This
    avoids expanding a dense hotspot's quadratic potential pairs just to count
    them. Bits name representatives; duplicate wrappers cannot inflate counts.
    """
    BLOCK = 128

    def __init__(self, members, index):
        self.index = index
        self.members = sorted(set(members), key=lambda i: (index.times[i], i))
        self.times = [index.times[i] for i in self.members]
        from array import array
        from app.services.capacity import execution_state
        # Store bit positions, not one N-bit integer for every member.
        self.compact = execution_state() is not None
        state = execution_state()
        self.block_cache = None
        if self.compact:
            from app.services.capacity import BoundedCache
            if not hasattr(state, 'posting_block_cache'):
                state.posting_block_cache = BoundedCache(256)
            self.block_cache = state.posting_block_cache
            self.times = array('q', self.times)
        positions = (index.positions[index.owner[i]] for i in self.members)
        self.bits = array('I', positions) if self.compact else [1 << pos for pos in positions]
        self.blocks = []
        self.block_offsets = []
        for offset in range(0, len(self.bits), self.BLOCK):
            mask = 0
            shift = min(self.bits[offset:offset + self.BLOCK]) if self.compact else 0
            for bit in self.bits[offset:offset + self.BLOCK]:
                mask |= (1 << (bit - shift)) if self.compact else bit
            self.blocks.append(zlib.compress(mask.to_bytes((mask.bit_length()+7)//8,'little'),1) if self.compact else mask)
            self.block_offsets.append(shift)
        if self.compact:
            self.runs = PostingRuns(self)
            return
        runs = defaultdict(lambda: defaultdict(list))
        for aid in self.members:
            rep = index.owner[aid]
            run = runs[index.times[aid]]
            run[rep].append(aid)
        self.runs = {stamp: sorted((rep, tuple(sorted(ids))) for rep, ids in run.items()) for stamp, run in runs.items()}
        self.member_positions = {aid: pos for pos, aid in enumerate(self.members)}
        self.group_positions = defaultdict(list)
        for pos, aid in enumerate(self.members):
            self.group_positions[index.owner[aid]].append(pos)

    def bounds(self, start, end):
        return bisect_left(self.times, start), bisect_right(self.times, end)

    def member_position(self, aid):
        if not self.compact:
            return self.member_positions.get(aid)
        stamp = self.index.times.get(aid)
        if stamp is None:
            return None
        lo, hi = self.bounds(stamp, stamp)
        pos = bisect_left(self.members, aid, lo, hi)
        return pos if pos < hi and self.members[pos] == aid else None

    def block_mask(self, block):
        if not self.compact:
            return self.blocks[block]
        # Bytes own their exact compressed mask; cache by bytes avoids object
        # lifetime/id-reuse hazards and does not retain the posting itself.
        payload = self.blocks[block]
        if payload not in self.block_cache:
            self.block_cache[payload] = int.from_bytes(zlib.decompress(payload),'little')
        return self.block_cache[payload]

    def mask(self, start, end, excluded=()):
        lo, hi = self.bounds(start, end)
        original_lo = lo
        mask = 0
        while lo < hi and lo % self.BLOCK:
            mask |= (1 << self.bits[lo]) if self.compact else self.bits[lo]
            lo += 1
        while lo + self.BLOCK <= hi:
            block = lo // self.BLOCK
            mask |= self.block_mask(block) << self.block_offsets[block]
            lo += self.BLOCK
        while lo < hi:
            mask |= (1 << self.bits[lo]) if self.compact else self.bits[lo]
            lo += 1
        removed = defaultdict(int)
        for aid in excluded:
            pos = self.member_position(aid)
            if pos is not None and original_lo <= pos < hi:
                removed[self.index.owner[aid]] += 1
        for rep, count in removed.items():
            in_range = (sum(pos is not None and original_lo <= pos < hi
                for pos in (self.member_position(aid) for aid in self.index.groups[rep])) if self.compact else
                bisect_left(self.group_positions[rep], hi) - bisect_left(self.group_positions[rep], original_lo))
            if count == in_range:
                mask &= ~(1 << self.index.positions[rep])
        return mask

    def nearest(self, member, start, end, limit, excluded=()):
        """Yield nearest unique groups, tie-breaking by representative ID.

        Timestamp ties are treated together so an input/member ID never chooses
        a different retained representative. Window filtering precedes top-K.
        """
        lo, hi = self.bounds(start, end)
        center = self.index.times[member]
        split = bisect_left(self.times, center, lo, hi)
        left, right = split - 1, split
        seen = {self.index.owner[member]}
        yielded = 0
        while (left >= lo or right < hi) and yielded < limit:
            ld = center - self.times[left] if left >= lo else math.inf
            rd = self.times[right] - center if right < hi else math.inf
            gap = min(ld, rd)
            hits = {}
            if ld == gap:
                begin = bisect_left(self.times, self.times[left], lo, left + 1)
                for rep, aids in self.runs[self.times[left]]:
                    aid = next((i for i in aids if i not in excluded), None)
                    if aid is None:
                        continue
                    if rep not in seen and aid not in excluded:
                        hits[rep] = min(aid, hits.get(rep, aid))
                    if len(hits) >= limit - yielded:
                        break
                left = begin - 1
            if rd == gap:
                stop = bisect_right(self.times, self.times[right], right, hi)
                right_hits = 0
                for rep, aids in self.runs[self.times[right]]:
                    aid = next((i for i in aids if i not in excluded), None)
                    if aid is None:
                        continue
                    if rep not in seen and aid not in excluded:
                        hits[rep] = min(aid, hits.get(rep, aid))
                        right_hits += 1
                    if right_hits >= limit - yielded:
                        break
                right = stop
            for rep in sorted(hits):
                seen.add(rep)
                yield rep, hits[rep], gap / 1000000
                yielded += 1
                if yielded == limit:
                    break


class AlertIndex:
    def __init__(self, alerts, groups=(), entities=()):
        from app.services.capacity import AlertSequence, AlertMap
        bounded_alerts = alerts.mapping if isinstance(alerts, AlertSequence) else alerts if isinstance(alerts, AlertMap) else None
        self.alerts = {}
        for item in alerts:
            a = item if bounded_alerts is not None else CanonicalAlert.model_validate(item.model_dump() if hasattr(item, "model_dump") else item)
            reject_truth(a.raw_alert)
            if id_for("CanonicalAlert", a) != a.alert_id:
                raise ValueError("alert_identity_mismatch")
            if a.alert_id in self.alerts and self.alerts[a.alert_id] != a:
                raise ValueError("same_alert_id_conflicting_content")
            if bounded_alerts is None:
                self.alerts[a.alert_id] = a
        self.alerts = bounded_alerts if bounded_alerts is not None else dict(sorted(self.alerts.items()))
        self.entities = {}
        for item in entities:
            e = Entity.model_validate(item.model_dump() if hasattr(item, "model_dump") else item)
            if id_for("Entity", e) != e.entity_id or any(aid not in self.alerts for aid in e.alert_ids):
                raise ValueError("entity_identity_or_reference_mismatch")
            if e.entity_id in self.entities and self.entities[e.entity_id] != e:
                raise ValueError("conflicting_entity")
            self.entities[e.entity_id] = e
        self.entities = dict(sorted(self.entities.items()))
        self.owner = {i: i for i in self.alerts}
        assigned = set()
        for item in groups:
            g = DedupeGroup.model_validate(item.model_dump() if hasattr(item, "model_dump") else item)
            if id_for("DedupeGroup", g) != g.group_id or any(aid not in self.alerts for aid in g.alert_ids):
                raise ValueError("group_identity_or_reference_mismatch")
            if assigned.intersection(g.alert_ids):
                raise ValueError("overlapping_dedupe_groups")
            assigned.update(g.alert_ids)
            for i in g.alert_ids:
                self.owner[i] = g.representative_alert_id
        members = defaultdict(list)
        for aid, rep in self.owner.items():
            members[rep].append(aid)
        self.groups = {rep: tuple(sorted(ids)) for rep, ids in sorted(members.items())}
        self.representatives = tuple(self.groups)
        self.N = len(self.groups)
        self.positions = {rep: pos for pos, rep in enumerate(self.representatives)}
        self.times = {aid: event_microseconds(a) for aid, a in self.alerts.items()}
        from app.services.capacity import execution_state, DiskScalarObjects
        state = execution_state()
        self.roles = DiskScalarObjects(state.database(), 'entity_roles') if state else {}
        entity_members, source_members, sensor_members = defaultdict(list), defaultdict(list), defaultdict(list)
        actual_refs = defaultdict(set)
        self.monitored_ip_entities = set()
        for aid, a in self.alerts.items():
            roles = defaultdict(set)
            for occurrence in a.entity_occurrences:
                if occurrence.entity_id not in self.entities:
                    raise ValueError("missing_entity_reference")
                resolve_pointer(a.raw_alert, occurrence.raw_pointer)
                roles[occurrence.entity_id].add(occurrence.role.value)
                actual_refs[occurrence.entity_id].add(aid)
                if occurrence.role.value == "monitored_host_ip":
                    self.monitored_ip_entities.add(occurrence.entity_id)
            self.roles[aid] = dict(roles)
            for eid in roles:
                entity_members[eid].append(aid)
            source_members[a.source_type.value].append(aid)
            if a.sensor:
                sensor_members[a.sensor].append(aid)
            for relation in a.relations:
                for p in relation.raw_pointers:
                    p.resolve(self.alerts)
        if any(set(e.alert_ids) != actual_refs[eid] for eid, e in self.entities.items()):
            raise ValueError("entity_occurrence_closure_mismatch")
        self.df = {eid: len({self.owner[i] for i in ids}) for eid, ids in entity_members.items()}
        self.time = self.postings(self.alerts)
        self.by_entity = {eid: self.postings(ids) for eid, ids in sorted(entity_members.items())}
        from app.entities.context import context_key
        self.front_data = any(a.extraction_version == 'front-data-v1' for a in self.alerts.values())
        context_members, self.context_refs, self.contexts_by_alert = defaultdict(set), {}, {}
        for aid, a in self.alerts.items():
            keys = set()
            for ref in a.contexts:
                key = context_key(ref)
                keys.add(key)
                context_members[key].add(aid)
                self.context_refs[key] = ref
            self.contexts_by_alert[aid] = keys
        self.by_context = {key: self.postings(ids) for key, ids in sorted(context_members.items())}
        self.context_members = {key: tuple(sorted(ids)) for key, ids in sorted(context_members.items())}
        self.df.update({key: len({self.owner[aid] for aid in ids}) for key, ids in context_members.items()})
        self.bridge_posting_cache = {}
        self.by_source = {key: self.postings(ids) for key, ids in sorted(source_members.items())}
        self.by_sensor = {key: self.postings(ids) for key, ids in sorted(sensor_members.items())}
        if state and hasattr(state, 'progress'):
            postings = [*self.time.values(), *(p for collection in (self.by_entity, self.by_source, self.by_sensor)
                for categories in collection.values() for p in categories.values())]
            state.progress(dict(stage='compact_index_ready', alert_count=len(self.alerts),
                representatives=self.N, entities=len(self.entities), postings=len(postings),
                posting_members=sum(len(p.members) for p in postings),
                compressed_block_bytes=sum(len(b) for p in postings for b in p.blocks),
                role_cache_entries=len(self.roles.cache)))

    def postings(self, members):
        categories = defaultdict(list)
        for i in members:
            categories[self.alerts[i].category.value].append(i)
        return {c: TemporalPosting(ids, self) for c, ids in sorted(categories.items())}

    def compatible_entity_postings(self, member, eid):
        """Partition new role bridges before temporal nearest-K and hot caps."""
        from .entity_bridges import compatible, MONITORED
        e = self.entities[eid]
        if eid not in self.monitored_ip_entities:
            return self.by_entity[eid]
        a = self.alerts[member]
        key = (eid, a.source_type.value, tuple(sorted(self.roles[member][eid])))
        if key not in self.bridge_posting_cache:
            self.bridge_posting_cache[key] = self.postings(aid for aid in e.alert_ids if compatible(self, member, aid, eid))
        return self.bridge_posting_cache[key]

    def semantic_index(self, fields):
        """Source-scoped inverted indexes, limited to entity-free alerts.

        Existing entity channels already cover host/account/session/network
        sparsity. Semantic fallback cannot displace those candidates globally.
        """
        from app.utils.stable_id import content_digest
        buckets, memberships = defaultdict(list), defaultdict(list)
        for aid, alert in self.alerts.items():
            if alert.entity_ids:
                continue
            for field in fields:
                value = getattr(alert, field)
                value = value.value if field == "category" else value
                if value is None or field == "category" and value == "unknown":
                    continue
                key = "semantic_" + content_digest([field, alert.source_namespace, value])
                buckets[key].append(aid)
                memberships[aid].append(key)
        postings = {}
        for key, aids in sorted(buckets.items()):
            postings[key] = self.postings(aids)
            self.df[key] = len({self.owner[aid] for aid in aids})
        return postings, memberships

    def query_time(self, start, end):
        lo_time = event_microseconds(start)
        hi_time = event_microseconds(end)
        members = []
        for posting in self.time.values():
            lo, hi = posting.bounds(lo_time, hi_time)
            members.extend(posting.members[lo:hi])
        return sorted((self.alerts[i] for i in members), key=lambda a: (a.timestamp, a.alert_id))

    def query_entity(self, entity_id, start, end, role=None):
        e = self.entities.get(entity_id)
        if e is None:
            return []
        return sorted((self.alerts[i] for i in e.alert_ids if start <= self.alerts[i].timestamp <= end
                       and (role is None or role in self.roles[i][entity_id])), key=lambda a: (a.timestamp, a.alert_id))

    def query_context(self, kind, value, scope):
        from app.entities.context import context_key
        from app.models.alerts import ContextRef
        key = context_key(ContextRef(kind=kind, value=value, scope=scope, raw_pointer=''))
        return [self.alerts[aid] for aid in self.context_members.get(key, ())]

    def rarity(self, eid, parameters):
        if not parameters.rarity_enabled:
            return 1.0
        smoothing = parameters.rarity_smoothing
        return max(parameters.rarity_floor, min(1.0, math.log((self.N + smoothing) / (self.df[eid] + smoothing))
                                               / math.log(self.N + smoothing)))

    def frequency_snapshot(self):
        snapshot = {"N": self.N, "scope": "analysis_representatives", "frequency_unit": "dedupe_group",
                "entities": [{"entity_id": eid, "type": e.type.value, "scope": e.scope, "value": e.value,
                              "df": self.df[eid]} for eid, e in self.entities.items()]}
        if self.front_data:
            snapshot['extraction_contract'] = 'front-data-v1'
            snapshot['contexts'] = [dict(key=key, kind=ref.kind, scope=ref.scope, value=ref.value, df=self.df[key])
                                    for key, ref in sorted(self.context_refs.items())]
        return snapshot

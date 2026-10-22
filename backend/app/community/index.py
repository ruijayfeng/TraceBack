"""Bounded, time-ordered postings; never scans a global alert/time pair table."""
from collections import defaultdict, deque

from .evidence import evidence_tier


class CommunityIndex:
    def __init__(self, config):
        self.config = config
        self.postings = defaultdict(deque)
        self.examined = 0
        self.policy_pruned = 0

    @staticmethod
    def typed_key(binding):
        # A context value or partial tuple can never share a strong-key bucket.
        return binding.projection, binding.kind, binding.key

    def query(self, profile):
        found = []
        for binding in profile.bindings:
            rows = self.postings.get(self.typed_key(binding))
            if not rows:
                continue
            window = (self.config.windows_seconds[str(binding.level)] if evidence_tier(binding.kind) == 'A'
                      else self.config.temporal.max_seconds)
            while rows and profile.seconds-rows[0][0].seconds > window:
                rows.popleft()
            for other, prior_binding in reversed(rows):
                self.examined += 1
                found.append((profile, other, binding, prior_binding))
        found.sort(key=lambda row: (evidence_tier(row[2].kind), row[2].level, profile.seconds-row[1].seconds,
                                    row[1].alert.alert_id, row[2].kind, row[2].key, row[3].role))
        # Cap distinct alert neighbors, keeping all evidence for admitted pairs.
        admitted = set()
        output = []
        dropped = set()
        for row in found:
            aid = row[1].alert.alert_id
            if aid not in admitted and len(admitted) >= self.config.max_candidates_per_alert:
                dropped.add(aid)
                continue
            admitted.add(aid)
            output.append(row)
        self.policy_pruned += len(dropped)
        return output

    def add(self, profile):
        for binding in profile.bindings:
            rows = self.postings[self.typed_key(binding)]
            rows.append((profile, binding))
            while len(rows) > self.config.max_witnesses_per_key:
                rows.popleft()
                self.policy_pruned += 1

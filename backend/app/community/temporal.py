"""Candidate-component cadence, calculated only from already admitted members."""
from dataclasses import dataclass, field
from math import sqrt


@dataclass
class TemporalHistory:
    times: list[float] = field(default_factory=list)

    def snapshot(self, policy):
        ordered = sorted(self.times)
        intervals = [b - a for a, b in zip(ordered, ordered[1:])]
        n = len(intervals)
        mean = sum(intervals) / n if n else None
        std = sqrt(sum((gap - mean) ** 2 for gap in intervals) / n) if n else None
        fallback = n < policy.min_intervals
        threshold = policy.fallback_seconds if fallback else mean + std
        threshold = min(policy.max_seconds, max(policy.min_seconds, threshold))
        return dict(interval_count=n, mean_interval_seconds=mean,
                    interval_std_seconds=std, dynamic_threshold_seconds=threshold,
                    fallback_used=fallback)

    def compatible(self, delta, policy):
        return delta <= self.snapshot(policy)['dynamic_threshold_seconds']

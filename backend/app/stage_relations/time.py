"""Time validates semantic direction, and orders weak observations only."""
from datetime import datetime
from .models import TimeFacts


def seconds(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def gap_seconds(later, earlier):
    # Timedelta preserves microseconds at the tolerance boundary.
    return (datetime.fromisoformat(later.replace('Z', '+00:00'))-
            datetime.fromisoformat(earlier.replace('Z', '+00:00'))).total_seconds()


def time_facts(a, b, evidence, alerts, policy):
    if a.end_time < b.start_time:
        order, gap = 'A_BEFORE_B', gap_seconds(b.start_time,a.end_time)
    elif b.end_time < a.start_time:
        order, gap = 'B_BEFORE_A', gap_seconds(a.start_time,b.end_time)
    else:
        order, gap = 'OVERLAP_OR_EQUAL', 0.0
    d = evidence.semantic_direction
    semantic_gap = gap_seconds(alerts[d.to_alert_id].timestamp,alerts[d.from_alert_id].timestamp) if d else None
    conflict = semantic_gap is not None and semantic_gap < -policy.time_reversal_tolerance_seconds
    consistency = ('conflict' if conflict else 'within_tolerance' if semantic_gap is not None and semantic_gap < 0
                   else 'overlap' if order == 'OVERLAP_OR_EQUAL' else 'consistent')
    facts = TimeFacts(stage_a_start=a.start_time, stage_a_end=a.end_time,
        stage_b_start=b.start_time, stage_b_end=b.end_time,
        primary_alert_timestamps={aid: alerts[aid].timestamp for aid in evidence.alert_ids},
        semantic_gap_seconds=semantic_gap, tolerance_seconds=policy.time_reversal_tolerance_seconds,
        rule='TIME_CONFLICT' if conflict else 'SEMANTIC_WITNESS_WITHIN_TOLERANCE' if d else 'DISJOINT_STAGE_OBSERVATION_ORDER')
    return order, float(gap), order == 'OVERLAP_OR_EQUAL', conflict, consistency, facts

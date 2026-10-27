"""Official ①–⑧ orchestration, stopping after cross-Stage evidence validation."""
from collections import Counter
from dataclasses import dataclass

from app.community import load_community_config, prepare_communities
from app.community.builder import CommunityRun
from app.services.alert_pipeline import NormalizedAlerts, ROOT, load_alert_pipeline
from app.stages.config import load_stage_config
from app.stages.models import StageResult
from app.stage_candidates import StagePairCandidateResult, load_candidate_config, generate_stage_pair_candidates
from app.stage_evidence import CrossStageEvidenceResult, load_evidence_config, validate_stage_pair_candidates
from app.services.pipeline_progress import notify

OFFICIAL_STAGE_PIPELINE_ENTRY = 'app.services.stage_pipeline.load_stage_pipeline'


@dataclass
class StagePipelineRun:
    normalized: NormalizedAlerts
    community: CommunityRun
    stages: StageResult
    candidate_result: StagePairCandidateResult
    evidence_result: CrossStageEvidenceResult

    @property
    def candidates(self):
        return self.candidate_result.candidates

    @property
    def statistics(self):
        alerts = {a.alert_id: a for a in self.community.alerts}
        communities = self.community.result.incident_candidates
        membership = Counter(i for c in communities for i in c.alert_ids)
        stage_membership = Counter(i for s in self.stages.stages for i in s.alert_ids)
        owner = {i: c.community_id for c in communities for i in c.alert_ids}
        pointers = [p for c in communities for e in c.matching_evidence for p in e.supporting_evidence]
        pointers += [p for s in self.stages.stages for e in s.aggregation_basis for p in e.evidence]
        pointers += [p for b in self.stages.behaviors for p in b.evidence]
        invalid = 0
        for pointer in pointers:
            try:
                pointer.resolve(alerts)
            except (ValueError, KeyError, IndexError, TypeError):
                invalid += 1
        missing_communities = len(set(alerts) - membership.keys())
        missing_stages = len(set(alerts) - stage_membership.keys())
        duplicate_communities = sum(n-1 for n in membership.values())
        duplicate_stages = sum(n-1 for n in stage_membership.values())
        cross = sum(any(owner.get(i) != s.community_id for i in s.alert_ids) for s in self.stages.stages)
        dangling = len((membership.keys() | stage_membership.keys() | {p.alert_id for p in pointers}) - alerts.keys())
        empty = sum(not s.alert_ids for s in self.stages.stages)
        if any((missing_communities, missing_stages, duplicate_communities, duplicate_stages,
                cross, dangling, invalid, empty)):
            raise ValueError('stage_pipeline_partition_or_evidence_invalid')
        upstream = dict(OFFICIAL_PIPELINE_ENTRY=OFFICIAL_STAGE_PIPELINE_ENTRY,
            **self.normalized.noise_filter.statistics,
            COMMUNITY_COUNT=len(communities), COMMUNITY_SIZES=sorted(c.member_count for c in communities),
            COMMUNITY_ALERT_TOTAL=sum(membership.values()),
            **{**self.stages.statistics, 'CURRENT_PIPELINE_STAGE': '⑥ Community → Stage'},
            STAGE_SIZES=sorted(s.alert_count for s in self.stages.stages),
            UNASSIGNED_COMMUNITY_ALERT_COUNT=missing_communities,
            DUPLICATE_COMMUNITY_MEMBERSHIP_COUNT=duplicate_communities,
            UNASSIGNED_STAGE_ALERT_COUNT=missing_stages, DUPLICATE_STAGE_MEMBERSHIP_COUNT=duplicate_stages,
            CROSS_COMMUNITY_STAGE_COUNT=cross, EMPTY_STAGE_COUNT=empty,
            DANGLING_ALERT_REFERENCE_COUNT=dangling, INVALID_EVIDENCE_POINTER_COUNT=invalid,
            EVIDENCE_POINTERS_CHECKED=len(pointers),
            NEXT_STAGE_STARTED=False)
        return {**upstream, **{k:v for k,v in self.candidate_result.statistics.items()
                              if k not in {'INPUT_ALERTS', 'COMMUNITY_COUNT'}},
                **{k:v for k,v in self.evidence_result.statistics.items() if k != 'INPUT_ALERTS'}}


def prepare_stage_pipeline(prepared, *, community_config=None, behavior_config=None, candidate_config=None, evidence_config=None, progress=None):
    """Consume an already completed ①–④ handoff; never re-run precursors."""
    from app.stages import aggregation
    if not isinstance(prepared, NormalizedAlerts) or prepared.entities is None:
        raise ValueError('stage_pipeline_requires_bound_normalized_alerts')
    prepared.validate_handoff()
    community_policy = community_config or load_community_config(ROOT/'configs/community-v1.yaml')
    behavior_policy = behavior_config or load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    notify(progress, 5, 'RUNNING')
    community = prepare_communities(prepared, prepared.source_settings, community_policy)
    notify(progress, 5, 'COMPLETED')
    notify(progress, 6, 'RUNNING')
    stages = aggregation.aggregate_stages(community, prepared.source_settings, community_policy, behavior_policy)
    notify(progress, 6, 'COMPLETED')
    candidate_policy = candidate_config or load_candidate_config(ROOT/'configs/stage-candidates-v1.yaml')
    notify(progress, 7, 'RUNNING')
    candidates = generate_stage_pair_candidates(stages, community.alerts, community.entities,
        prepared.source_settings, community_policy, candidate_policy)
    notify(progress, 7, 'COMPLETED')
    evidence_policy = evidence_config or load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml')
    notify(progress, 8, 'RUNNING')
    evidence = validate_stage_pair_candidates(candidates, stages, community.alerts, community.entities,
        prepared.source_settings, community_policy, evidence_policy)
    result = StagePipelineRun(prepared, community, stages, candidates, evidence)
    result.statistics  # Verify partition and raw pointers before returning success.
    notify(progress, 8, 'COMPLETED')
    return result


def load_stage_pipeline(input_path, *, community_config=None, behavior_config=None, noise_config=None, candidate_config=None, evidence_config=None, progress=None):
    """Read native alerts once, execute ①–⑧ once, return decisions without publishing.

    No semantic resolver is enabled by this entry. ⑥ consumes ④ annotations.
    """
    prepared = load_alert_pipeline(input_path, behavior_config=behavior_config, noise_config=noise_config, progress=progress)
    return prepare_stage_pipeline(prepared, community_config=community_config, behavior_config=behavior_config,
                                  candidate_config=candidate_config, evidence_config=evidence_config, progress=progress)

"""Official ⑧ cross-Stage witness validation; no relation graph construction."""
from .config import EvidenceConfig, load_evidence_config
from .models import CrossStageEvidence  # historical raw-witness reader only
from .contracts import (EvidenceClaim, ContextIdentityPosting, EvidenceTraceIndex,
    SupportingObservation, StageRelationDecision, CrossStageEvidenceResult)
from .validation import validate_stage_pair_candidates

__all__ = ['EvidenceConfig', 'load_evidence_config', 'CrossStageEvidence',
    'StageRelationDecision', 'CrossStageEvidenceResult', 'validate_stage_pair_candidates',
    'EvidenceClaim','ContextIdentityPosting','EvidenceTraceIndex','SupportingObservation']

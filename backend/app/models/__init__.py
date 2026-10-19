"""Single public entry point for the frozen TraceBack domain contract."""

from .enums import (
    AlertRelationType, AnalysisStatus, Category, ChainRelationType, ClaimKind,
    ClaimSection, EntityRole, EntityType, GroundingStatus, IncidentStatus,
    ReasonCode, Severity, SourceIndependence, SourceType,
    CHAIN_RELATION_MAPPING, CHAIN_RELATION_PRIORITY,
)
from .alerts import (AlertRelation, CanonicalAlert, Entity, EntityOccurrence,
                     EvidencePointer, FieldProvenance, ProcessRef, SupportPair)
from .reasons import (Reason, TimeGapParams, SharedEntityParams, ExplicitRelationParams,
                      BehaviorTransitionParams, SourceComplementParams, ConflictParams,
                      DuplicateParams, DirectionParams, ClusteringGuardParams, NodeBasisParams)
from .scoring import ScoreBreakdown, ScoreContributions, ScoreWeights
from .domain import AttackChain, ChainEdge, ChainNode, CorrelationEdge, DedupeGroup, Incident
from .ai import AIClaim, AIExplanation, AttackMapping, GroundedProposition
from .analysis import AnalysisMetrics, AnalysisRecord, EvaluationSummaryExport

__all__ = [
    "AlertRelationType", "AnalysisStatus", "Category", "ChainRelationType", "ClaimKind", "ClaimSection",
    "EntityRole", "EntityType", "GroundingStatus", "IncidentStatus", "ReasonCode", "Severity",
    "SourceIndependence", "SourceType", "CHAIN_RELATION_MAPPING", "CHAIN_RELATION_PRIORITY",
    "AlertRelation", "CanonicalAlert", "Entity", "EntityOccurrence", "EvidencePointer", "FieldProvenance",
    "ProcessRef", "SupportPair", "Reason", "TimeGapParams", "SharedEntityParams", "ExplicitRelationParams",
    "BehaviorTransitionParams", "SourceComplementParams", "ConflictParams", "DuplicateParams", "DirectionParams",
    "ClusteringGuardParams", "NodeBasisParams", "ScoreBreakdown", "ScoreContributions", "ScoreWeights",
    "AttackChain", "ChainEdge", "ChainNode", "CorrelationEdge", "DedupeGroup", "Incident", "AIClaim",
    "AIExplanation", "AttackMapping", "GroundedProposition", "AnalysisMetrics", "AnalysisRecord", "EvaluationSummaryExport",
]

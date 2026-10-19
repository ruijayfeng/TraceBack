"""Stage-pair analysis only; no path assembly or downstream side effects."""
from .analysis import analyze_stage_relations
from .config import load_relation_config
from .models import StageRelation, StageRelationResult

__all__ = ['analyze_stage_relations', 'load_relation_config', 'StageRelation', 'StageRelationResult']

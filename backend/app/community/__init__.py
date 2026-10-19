"""CanonicalAlert -> scoped evidence -> bounded index -> incident candidates."""
from .builder import build_communities, prepare_communities, CommunityRun
from .config import CommunityConfig, load_community_config
from .models import CommunityResult, IncidentCandidate, MatchingEvidence

__all__ = ['build_communities', 'prepare_communities', 'CommunityRun',
           'CommunityConfig', 'load_community_config', 'CommunityResult',
           'IncidentCandidate', 'MatchingEvidence']

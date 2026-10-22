"""⑦ retrieval only; no dependency on downstream Stage relation modules."""
from .config import CandidateConfig, load_candidate_config
from .generator import generate_stage_pair_candidates
from .models import StagePairCandidate, StagePairCandidateResult

__all__ = ['CandidateConfig', 'load_candidate_config', 'generate_stage_pair_candidates',
           'StagePairCandidate', 'StagePairCandidateResult']

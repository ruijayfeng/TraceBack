"""Official ⑨ handoff after the unchanged ①–⑧ service completes."""
from dataclasses import dataclass

from app.services.stage_pipeline import StagePipelineRun, load_stage_pipeline
from app.services.pipeline_progress import notify
from .reconstruction import (AttackChainReconstruction, FrozenStageGraph,
                             reconstruct_attack_chains, validate_reconstruction)


@dataclass
class AttackChainPipelineRun:
    upstream: StagePipelineRun
    graph: FrozenStageGraph
    reconstruction: AttackChainReconstruction

    @property
    def statistics(self):
        return {**self.upstream.statistics,
                'OFFICIAL_PIPELINE_ENTRY': 'scripts/run_stage_pipeline.py',
                'CURRENT_PIPELINE_STAGE': '⑨ Attack Chain Reconstruction',
                'STAGE_9_STARTED': True, 'NEXT_STAGE_STARTED': False,
                'ATTACK_CHAIN_COUNT': len(self.reconstruction.chains),
                'SINGLE_STAGE_CHAIN_COUNT': sum(c.single_stage for c in self.reconstruction.chains)}


def load_attack_chain_pipeline(input_path, **upstream_options):
    """Read native input once; consume exactly the returned formal ⑧ objects."""
    upstream = load_stage_pipeline(input_path, **upstream_options)
    notify(upstream_options.get('progress'), 9, 'RUNNING')
    graph = FrozenStageGraph.from_stage8(upstream.stages.stages,
        upstream.evidence_result, upstream.community.alerts)
    reconstruction = reconstruct_attack_chains(graph)
    validate_reconstruction(reconstruction, graph)
    notify(upstream_options.get('progress'), 9, 'COMPLETED')
    return AttackChainPipelineRun(upstream, graph, reconstruction)

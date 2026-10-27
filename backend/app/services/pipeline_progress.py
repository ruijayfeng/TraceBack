"""Read-only execution notifications; numbering follows the frozen pipeline."""

STAGES = (
    '① 告警统一标准化', '② 实体提取与绑定', '③ 告警噪声抑制', '④ 行为语义标准化',
    '⑤ Community', '⑥ Community → Stage', '⑦ Stage Pair Candidate Generation',
    '⑧ Cross-Stage Evidence Verification', '⑨ Attack Chain Reconstruction',
)


def notify(observer, stage, status):
    if observer is not None:
        observer(dict(stage=stage, name=STAGES[stage - 1], status=status))

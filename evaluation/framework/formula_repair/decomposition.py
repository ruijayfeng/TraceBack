"""Post-hoc decomposition of the immutable, already evaluated F2 run."""
import json
import math
from . import ROOT, OUT
from evaluation.framework.formula_design.runtime import read, save, sha


def run():
    source = ROOT/'outputs/v5_validation_threshold_calibration/ground_truth_edge_scores.json'
    original = read(source)
    policy = read(ROOT/'outputs/v5_formula_design/preparation.json')['policy']
    edges = {}
    for key, row in original['edges'].items():
        result = row['score_breakdown']
        dimensions={d['name']:d for name in ('supporting_evidence','weak_evidence','observed_zero_evidence','unavailable_evidence')
            for d in result[name]}
        available=[d for d in dimensions.values() if d['family']!='time' and d['state'] in {'SUPPORT','OBSERVED_ZERO','CONTRADICTORY'}]
        denominator=math.fsum(d['weight']*d['reliability'] for d in available)
        families={}
        for family in sorted({d['family'] for d in dimensions.values()}):
            ds=[d for d in available if d['family']==family]
            numerator=math.fsum(d['weight']*d['reliability']*d['strength'] for d in ds)
            families[family]=dict(dimensions=[dict(d,denominator_weight=d['weight']*d['reliability'] if d in available else 0.,
                numerator=d['weight']*d['reliability']*d['strength'] if d in available else 0.)
                for d in dimensions.values() if d['family']==family],
                numerator=numerator,denominator=math.fsum(d['weight']*d['reliability'] for d in ds),
                normalized_contribution=numerator/denominator if denominator else 0.)
        # Recover every evidence partition from the delivered F2 explanation.
        edges[key] = dict(original=row, formula=result,candidate_channels=row['candidate_generation_reason'],
            gate_decisions=row['gates'],feature_family_contributions=families,
            quality_normalization=dict(denominator=denominator,
                numerator=math.fsum(d['weight']*d['reliability']*d['strength'] for d in available),
                normalized_support=result['support_score'],coverage=result['coverage_confidence'],
                temporal_factor=policy['time_floor']+(1-policy['time_floor'])*result['temporal_compatibility']),
            positive_evidence=result['supporting_evidence'],zero_evidence=result['observed_zero_evidence'],
            unavailable_evidence=result['unavailable_evidence'],negative_contradictions=result['contradictions'],
            final_score=row['score'],
            downstream_eligibility=dict(clustering=row['score'] >= .70,
                chain_score=row['score'] >= .70, explicit_relation=False),
            explanation='F2 hybrid requires a contextual entity/relation role; quality divides by all observed non-time dimensions including zero alternatives.')
    save(OUT/'failure_decomposition.json', dict(source_sha256=sha(source), edges=edges,
        F2_policy=policy, historical_artifacts_modified=False,
        failures=dict(gate='role whitelist is a sufficiency policy, not an immutable contradiction',
            separation='observed alternative paths/metadata zeros dilute independent support; role ceilings compress sparse evidence',
            threshold='all F2 scores below downstream 0.70',
            downstream='no verified AlertRelation in the six witness score explanations',
            contract='no F2 production ScoreBreakdown serializer or dispatch')))
    save(OUT/'gate_analysis.json', dict(classification='OVER_RESTRICTIVE_GATE',
        rule='F2 hybrid: contextual or strong', relation_family='entity/relation',
        GT_E01=dict(gates=edges['GT-E01']['original']['gates'],
            features=edges['GT-E01']['original']['main_positive_evidence'],
            score=edges['GT-E01']['original']['score']),
        general_reason='Ordinary IP/domain is weak context, not a contradiction. A soft ceiling can prevent strong admission without a role-based hard reject.',
        retained_hard_gates=['hard namespace/session contradiction','same observation','no non-temporal context'],
        direction_gate='VALID_SAFETY_GATE: explicit field-attested propagation remains mandatory'))
    print('F2_DECOMPOSITION_SAVED', flush=True)


if __name__ == '__main__':
    run()

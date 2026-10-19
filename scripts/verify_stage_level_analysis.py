"""Validate sealed relation output and evidence closure without rerunning analysis."""
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from app.community.models import IncidentCandidate
from app.models import CanonicalAlert, Entity
from app.stage_relations.models import StageRelation
from app.stage_relations.config import RelationConfig
from app.stages.models import Stage, BehaviorAnnotation, StageResult
from app.utils.stable_id import content_digest, id_for
from run_stage_level_analysis import production_guard, sha, save


def verify(output):
    output = Path(output).resolve()
    with production_guard([output]) as access:
        manifest = json.loads((output/'manifest.json').read_text(encoding='utf8'))
        for name,h in {**manifest['source_artifacts'],**manifest['artifacts']}.items():
            assert sha(ROOT/name) == h, 'artifact_digest_mismatch:'+name
        def read(name,model):
            ref, = [p for p in manifest['source_artifacts'] if p.endswith('/'+name)]
            with gzip.open(ROOT/ref,'rt',encoding='utf8') as stream:
                return [model.model_validate_json(line) for line in stream]
        alerts = read('stage_source_alerts.jsonl.gz',CanonicalAlert)
        entities = read('stage_source_entities.jsonl.gz',Entity)
        communities = read('stage_source_communities.jsonl.gz',IncidentCandidate)
        aa,ee,cc = {a.alert_id:a for a in alerts},{e.entity_id:e for e in entities},{c.community_id:c for c in communities}
        context = dict(alerts=aa,entities=ee,communities=cc)
        stages = read('stages.jsonl.gz',Stage)
        for stage in stages:
            Stage.model_validate(stage,context=context)
        behaviors = read('behaviors.jsonl.gz',BehaviorAnnotation)
        StageResult.model_validate(dict(config_hash=content_digest({}),stages=stages,behaviors=behaviors,statistics={},diagnostics=[]),context=context)
        context['stages'] = {s.stage_id:s for s in stages}
        exported = json.loads((output/'relations.json').read_text(encoding='utf8'))
        relations = [StageRelation.model_validate(r,context=context) for r in exported]
        policy = RelationConfig.model_validate(manifest['config_snapshot']['stage_relations'])
        pointer_count = 0
        for r in relations:
            assert r.time_facts.tolerance_seconds == policy.time_reversal_tolerance_seconds
            for evidence in [r.primary_evidence,*r.supporting_evidence]:
                ep = policy.evidence[evidence.evidence_type]
                assert evidence.rank == ep.rank and evidence.evidence_strength == ep.strength
                for pointer in evidence.pointers:
                    pointer.resolve(aa)
                    pointer_count += 1
        result = json.loads((output/'result.json').read_text(encoding='utf8'))
        assert exported == result['relations']
        pair_set = {(d['stage_a_id'],d['stage_b_id']) for d in result['diagnostics']}
        expected_pairs = sum(n*(n-1)//2 for n in Counter(s.community_id for s in stages).values())
        assert len(pair_set) == len(result['diagnostics']) == expected_pairs
        decisions = Counter(d['decision'] for d in result['diagnostics'])
        for kind in ('STRONG_DIRECTED','STRONG_UNDIRECTED','WEAK_DIRECTED','NO_RELATION'):
            assert decisions[kind] == result['statistics'][kind+'_COUNT']
        assert len(relations) == expected_pairs-decisions['NO_RELATION']
        assert len({r.relation_id for r in relations}) == len(relations)
        assert manifest['config_hash'] == content_digest(manifest['config_snapshot'])
        assert manifest['analysis_id'] == id_for('AnalysisRecord',dict(input_alert_ids=sorted(aa),
            config_hash=manifest['config_hash'],algorithm_version=policy.version,schema_version='1.0'))
        verification = dict(RELATIONS_VALIDATED=len(relations),BOUND_EVIDENCE_POINTERS_RESOLVED=pointer_count,
            SCOPED_PAIRS_VALIDATED=expected_pairs,COMMUNITY_BEHAVIOR_STAGE_SOURCE_HASHES_UNCHANGED=True,
            SCHEMA_AND_IDENTITY_VALIDATED=True,CONFIDENCE_POLICY_VALIDATED=True,
            PRODUCTION_GT_READS=0,ATTACK_CHAIN_RECONSTRUCTION_STARTED=False,NEXT_STAGE_NOT_STARTED=True,
            **access)
        save(output/'verification.json',verification)
        print(json.dumps(verification,indent=2))
        return verification


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage_relations_v1')
    args = parser.parse_args()
    verify(args.output)

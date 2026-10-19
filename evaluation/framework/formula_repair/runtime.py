"""Freeze once; score the canonical snapshot under a GT-denying read guard."""
import gzip
import hashlib
import json
import sys
import time
from . import ROOT,OUT
from evaluation.framework.formula_design import BASELINE
from evaluation.framework.formula_design.runtime import read,save,sha,rows,guard


def freeze():
    from app.services.storage import restore_config
    from app.config import read_yaml
    from app.utils.stable_id import content_digest
    from app.correlation.formula_v5 import ALGORITHM_VERSION,IMPLEMENTATION_VERSION
    if (OUT/'formula_freeze.json').exists():raise ValueError('immutable_formula_freeze_exists')
    before=read(OUT/'before.json')
    for name,digest in before['protected_files'].items():
        if sha(ROOT/name)!=digest:raise ValueError('protected_changed:'+name)
    original=read(BASELINE/'preparation.json')
    # Use the exact accepted deployment/mappings; add only explicit new policy.
    snap=original['algorithm']
    snap['implementation_version']=IMPLEMENTATION_VERSION
    snap['score']['evidence_v5']=read_yaml(ROOT/'configs/algorithm-v5.yaml')['score']['evidence_v5']
    config=restore_config(snap)
    effective={'algorithm':config.snapshot,'sources':original['sources']}
    files={p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'backend/app').rglob('*.py')}
    files['configs/algorithm-v5.yaml']=sha(ROOT/'configs/algorithm-v5.yaml')
    save(OUT/'formula_freeze.json',dict(algorithm_version=ALGORITHM_VERSION,implementation_version=IMPLEMENTATION_VERSION,
        config_hash=content_digest(effective),mapping_digest=config.mapping_digest,effective=effective,
        formula_revision='F3-independent-support-v1',implementation_files=files,
        canonical_inputs={str(BASELINE/'blind'/name):sha(BASELINE/'blind'/name) for name in
            ('canonical.jsonl.gz','dedupe.jsonl.gz','entities.jsonl.gz')},
        rules_fixed_before_new_GT_evaluation=True,expected_candidate_digest=read(BASELINE/'blind_run_manifest.json')['candidate_digest']
            if 'candidate_digest' in read(BASELINE/'blind_run_manifest.json') else read(ROOT/'outputs/v5_formula_design/blind_manifest.json')['candidate_digest'],
        scale={'0.0':'no affirmative semantic support, hard contradiction, or duplicate-only observation',
               '0.3':'weak or sparse contextual support; below normal admission',
               '0.5':'moderate semantic corroboration; insufficient for protected merge',
               '0.7':'substantial independent contextual support or verified propagation',
               '1.0':'complete field-attested support index, never an attack probability'},
        thresholds={'admission':.65,'clustering':.70,'chain':.70,'direction':.75},
        rationale='Display admission can be weaker than a merge; chain uses same support scale plus independent direction/explicit relation guards.',
        capability='UNOBSERVABLE includes absent capability/fields; OBSERVED_ZERO means both observed and unmatched, but alternatives are not exclusive contradictions.',
        feature_profile='v4 canonical feature extraction and candidates retained unchanged; V5 execution and score schema are independent'))
    print('F3_FORMULA_FROZEN',flush=True)


def verify_freeze():
    frozen=read(OUT/'formula_freeze.json')
    for name,digest in frozen['implementation_files'].items():
        if sha(ROOT/name)!=digest:raise ValueError('formula_source_changed:'+name)
    return frozen


def blind():
    frozen=verify_freeze()
    if (OUT/'score_seal.json').exists() or (OUT/'evaluation_started.json').exists():raise ValueError('single_use_blind')
    from app.adapters.base import AdapterSettings
    from app.models import CanonicalAlert,DedupeGroup,Entity
    from app.services.storage import restore_config
    from app.correlation.edges import run_correlation,peak_memory_mb
    from app.correlation.evidence_v4 import EvidenceV4Evaluator
    from app.correlation import evidence_v5,formula_v5
    from app.dedup.observation import ObservationMatcher
    from app.services.capacity import AlertSequence,execution_state
    from app.correlation.evidence_v3 import EvidenceV3Evaluator
    from app.correlation.evidence import EvidenceEvaluator
    from app.correlation import entity_bridges
    peak_memory_mb()
    destination=OUT/'blind';destination.mkdir(exist_ok=False)
    paths=[BASELINE/'blind'/n for n in ('canonical.jsonl.gz','dedupe.jsonl.gz','entities.jsonl.gz')]
    allowed=[OUT/'formula_freeze.json',*paths]
    digest=hashlib.sha256();count=0;members=0
    with guard(allowed,destination) as (events,reads):
        config=restore_config(frozen['effective']['algorithm'])
        settings={k:AdapterSettings(**v) for k,v in frozen['effective']['sources'].items()}
        alerts=[CanonicalAlert.model_validate(a) for a in rows(paths[0])]
        groups=[DedupeGroup.model_validate(a) for a in rows(paths[1])]
        entities=[Entity.model_validate(a) for a in rows(paths[2])]
        with gzip.open(destination/'diagnostics.jsonl.gz','wt',encoding='utf8',compresslevel=1) as detail, gzip.open(destination/'members.jsonl.gz','wt',encoding='utf8',compresslevel=1) as compact:
            def sink(row):
                nonlocal count,members
                if row['stage']=='candidate':
                    count+=1
                    digest.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
                if row['stage']=='member_score':
                    members+=1
                    compact.write(json.dumps(dict(support_pair=row['support_pair'],support_key=row['support_key'],
                        score=row['score'],valid=row['valid'],gate=row['evidence']['evidence_v5']['gate'],
                        relation_count=len(row['evidence']['relations'])),separators=(',',':'))+'\n')
                detail.write(json.dumps(row,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n')
            result=run_correlation(alerts,groups,entities,config,settings,diagnostic_sink=sink,
                progress=lambda row:print(json.dumps(row),flush=True))
        for name,objects in [('edges',result.edges)]:
            with gzip.open(destination/(name+'.jsonl.gz'),'wt',encoding='utf8') as f:
                for obj in objects:f.write(obj.canonical_json()+'\n')
        save(destination/'record.json',result.record.model_dump(mode='json'))
        save(destination/'summary.json',result.summary)
        save(destination/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),ground_truth_loaded=False,t2_read=False))
    actual=digest.hexdigest()
    save(OUT/'score_seal.json',dict(status='completed',ground_truth_loaded=False,
        formula_freeze_sha256=sha(OUT/'formula_freeze.json'),candidate_count=count,member_count=members,
        candidate_digest=actual,expected_candidate_digest=frozen['expected_candidate_digest'],
        candidate_identity_equal=actual==frozen['expected_candidate_digest'],
        files={p.relative_to(OUT).as_posix():sha(p) for p in destination.iterdir()}))
    if actual!=frozen['expected_candidate_digest']:raise ValueError('candidate_identity_changed')
    print('F3_BLIND_SCORES_SEALED',flush=True)


def verify_seal():
    verify_freeze()
    seal=read(OUT/'score_seal.json')
    if not seal['candidate_identity_equal'] or seal['ground_truth_loaded']:raise ValueError('unsealed')
    if sha(OUT/'formula_freeze.json')!=seal['formula_freeze_sha256']:raise ValueError('freeze_changed')
    for name,digest in seal['files'].items():
        if sha(OUT/name)!=digest:raise ValueError('score_artifact_changed:'+name)
    return seal


if __name__=='__main__':
    sys.path.insert(0,str(ROOT/'backend'))
    {'freeze':freeze,'blind':blind}[sys.argv[1]]()

"""Prospective semantics audit, frozen implementation and truth-denied scoring."""
import json
from pathlib import Path
from . import ROOT,OUT
from evaluation.framework.formula_design.runtime import read,save,sha
from evaluation.framework.formula_design import BASELINE

def prepare():
    """Verify old declared hashes and inventory history before any experiment."""
    import os
    if OUT.exists(): raise ValueError('new_output_directory_required')
    previous=read(ROOT/'outputs/v5_formula_repair_integration/before.json')
    declared={k:v for k,v in previous['protected_files'].items()
              if not k.startswith('backend/app/')}
    failures=[k for k,v in declared.items() if sha(ROOT/k)!=v]
    dataset_root=Path('D:/Code_WorkSpace/TraceBack-Dataset')
    failures.extend(k for k,v in previous['dataset_files'].items() if sha(dataset_root/k)!=v)
    if failures: raise ValueError(dict(historical_start_mismatch=failures))
    protected={str(ROOT/k):v for k,v in declared.items()}
    # Capture complete experiment artifacts, pruning disposable test workspaces.
    # Walking top-down avoids enumerating thousands of replicated fixture repos.
    for base in (ROOT/'outputs').iterdir():
        if not base.is_dir() or base==OUT: continue
        for directory,dirs,files in os.walk(base):
            dirs[:]=[d for d in dirs if not d.startswith(('pytest','regression_tmp','tmp','__pycache__'))
                     and d not in {'regression_isolated','.pytest_cache','node_modules','.venv'}]
            for name in files:
                p=Path(directory)/name
                protected[str(p)]=sha(p)
    for p in [ROOT/'AGENTS.md',*(ROOT/'docs').glob('*.md'),*(ROOT/'configs').rglob('*.yaml')]:
        protected[str(p)]=sha(p)
    for name in ('candidates.py','index.py','evidence_v4.py'):
        p=ROOT/'backend/app/correlation'/name;protected[str(p)]=sha(p)
    OUT.mkdir(parents=True,exist_ok=False)
    save(OUT/'historical_before.json',dict(protected_files=protected,dataset_files=previous['dataset_files'],
        previous_declared_hashes_verified=len(declared),
        production_start={p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'backend/app').rglob('*.py')},
        scope='Prior artifacts, including V4/V5 predictions, manifests, mappings and frozen dataset; disposable test directories excluded',
        inherited_implementation='Five-state candidate and tests already present at session entry; no final output existed'))
    save(OUT/'historical_start_verification.json',dict(status='PASS',failures=[],
        historical_count=len(protected),dataset_count=len(previous['dataset_files']),
        previous_declared_hashes_verified=len(declared),fresh_inventory=True))
    print('HISTORICAL_START_HASHES_VERIFIED',len(protected),flush=True)

def verify_history():
    before=read(OUT/'historical_before.json'); failures=[]
    for name,digest in before['protected_files'].items():
        if sha(Path(name))!=digest: failures.append(name)
    dataset_root=Path('D:/Code_WorkSpace/TraceBack-Dataset')
    for name,digest in before['dataset_files'].items():
        if sha(dataset_root/name)!=digest: failures.append(name)
    result=dict(status='PASS' if not failures else 'FAIL',failures=failures,
                historical_count=len(before['protected_files']),dataset_count=len(before['dataset_files']))
    if failures: raise ValueError(result)
    return result

def history_end():
    """Final historical hash pass; isolated result writes may continue."""
    result=verify_history()
    result['inventory_sha256']=sha(OUT/'historical_before.json')
    save(OUT/'historical_end_verification.json',result)
    print('HISTORICAL_END_HASHES_VERIFIED',flush=True)

def audit():
    families={
        'entity identity':'same canonical scoped entity; dependency joined to its typed fact',
        'IP continuity':'same scoped nonlocal endpoint; role/rarity and destination-only reductions retained',
        'host continuity':'canonical execution host in same asset scope',
        'account continuity':'same account in declared realm or within-source fallback scope',
        'domain continuity':'same normalized domain; hot-frequency quality retained',
        'URL/path continuity':'same target-scoped URL; URL/domain share resource group',
        'session continuity':'same scoped session; equality alone is undirected',
        'process continuity':'same process instance or discounted descriptor; execution group',
        'file/command continuity':'same scoped object; execution group',
        'network continuity':'existing distinct-flow/endpoint/behavior verifier; asset group',
        'transport continuity':'port/protocol alone never creates support; prerequisite to flow only',
        'detector identity':'same comparable detector metadata; audit-only, no independent group',
        'event/category relation':'configured compatibility; audit-only, cannot create context or direction',
        'role relation':'existing bound role modifiers; no independently accumulated fact',
        'direct relation':'field-verified relation with bound pointers; alternative sufficient pathway',
        'flow relation':'network continuity; same asset group, never causal attestation',
        'topology':'projection of verified flow/direct relation, no extra independent credit',
        'temporal relation':'positive exponential proximity modulates contextual mass, never standalone support',
        'propagation relation':'verified existing explicit relation; reversed direction is hard rejection',
        'source capability':'no product-name capability inference; absent fields MISSING, unknown comparison scope UNOBSERVABLE',
        'source complement':'confirmed independent complementary source context; audit-only, not extra underlying fact',
    }
    matrix=[]
    prerequisites={
        'IP continuity':'Both alerts have canonical src_ip or dst_ip in comparable network scope; role/rarity verifier must match',
        'host continuity':'Both alerts have canonical host with known comparable asset identity',
        'account continuity':'Both alerts have account and comparable realm or within-source fallback',
        'domain continuity':'Both alerts have normalized DOMAIN',
        'URL/path continuity':'Both alerts have URL and comparable target scope; bare unrelated relative paths do not match',
        'session continuity':'Both alerts have session and comparable application/session scope',
        'process continuity':'Both alerts have process/parent_process; instance and descriptor semantics retained',
        'file/command continuity':'Both alerts have the same typed field and comparable host/source scope',
        'network continuity':'Required src/dst, network scope, distinct-flow and mapped behavior facts satisfy existing verifier',
        'transport continuity':'Ports/protocol available as flow prerequisites; no standalone scored dimension',
        'detector identity':'Both comparable source-local detector/category metadata records exist; unlike detector values are neutral',
        'event/category relation':'Mapped categories exist; unknown category cannot assert incompatibility',
        'direct relation':'Existing relations can be verified with support-pair-bound pointers',
        'propagation relation':'Existing direct relation verifier proves operation/lineage/ordered flow; direction separately checked',
        'temporal relation':'Both required UTC canonical timestamps exist',
        'source complement':'Source independence established by existing attestation/mapping, plus complementary context',
        'source capability':'No exhaustive capability declaration exists; do not infer from product name; use fields and comparison scope only',
    }
    for name,condition in families.items():
        matrix.append(dict(family_name=name,observable_condition=prerequisites.get(name,'Derived view: observe only the existing bound underlying identity/relation facts'),
            applicable_condition=condition,support_condition='Existing bound positive verifier produces strength > 0',
            neutral_condition='Observable comparison produces zero support without explicit incompatibility proof',
            contradiction_condition='Only verified hard isolation, invalid/reversed explicit propagation or existing explicit conflict proof; distinct values alone are neutral',
            missing_condition='Required fields/relations absent; no source capability claim inferred',
            normalization_behavior='Positive support only; preserve existing role/rarity/source quality. No all-family average',
            denominator_behavior='Only positive dependency components enter agreement denominator; missing/unobservable/neutral excluded',
            gate_behavior='Only affirmative non-temporal fact enables scoring; existing hard/duplicate guards plus explicit reversed relation reject'))
    save(OUT/'evidence_semantics_matrix.json',dict(states=['MISSING','UNOBSERVABLE','OBSERVED_NEUTRAL','OBSERVED_SUPPORT','OBSERVED_CONTRADICTION'],families=matrix,
        limitation='Existing sources do not declare a comprehensive capability matrix; unknown capability is never invented. UNOBSERVABLE means known non-applicability, suppressed derived views, or unavailable comparison scope.',
        formula_definition=dict(groups='Conservative asset/resource/execution/ACCOUNT/SESSION components; shared entity IDs join views; max strength*reliability per component',
            semantic_agreement='sum(s_g*r_g)/sum(r_g) over positive components only; diagnostic quality, no completeness denominator',
            evidence_mass='1-product(1-s_g*r_g)',temporal_consistency='0.8+0.2*exp(-ln(2)*gap/half_life)',
            positive='max(verified_direct_strength*reliability, evidence_mass*temporal_consistency)',
            score='clamp(positive - 0.45*max(explicit_contradiction_strength) - 0.4*duplicate,0,1); single/nonindependent/hot-only context capped at 0.45; hard/duplicate gate => 0',
            diversity='>=2 independent positive non-hot components bypass single-clue ceiling; existing specific SESSION/PROCESS/direct proof pathway retained',
            evidence_independence='Dependency components; no new independence or completeness reward',role_consistency='Existing field-bound role factors; role absence never contradiction',
            source_capability='State classification only, never a negative or denominator term',theoretical_min=0.,theoretical_max=1.,
            sparse_case_reachability='3 independent moderate (.7 strength,.7 reliability) clues: (1-.51^3)*.8=0.6938792 without temporal support; with time=1 reaches 0.867349',
            medium_case_reachability='3 independent .8 strength/.8 reliability clues with time=1 => 0.953344',
            strong_case_reachability='Verified direct relation strength=1,reliability=1 =>1; hard guard always overrides',
            single_common_IP='strength<=1,reliability=.15 => <=.15; never promoted by time/metadata/derived views',
            contradiction_behavior='Explicit soft contradiction subtracts weighted penalty; hard isolation/duplicate/reversed explicit relation yields zero'),
        prospective_acceptance=dict(formula_changes=1,weights_changed=False,candidate_projection_changed=False,
            threshold_grid='.40 to .80 step .02 plus score boundaries and nextafter; scores sealed before GT read',
            production_acceptance='All 6 progression edges, 0/30 hard-alert FP against attack members, <=1000 background admissions, >=.02 operating interval, actual directed chain, regressions/history pass',
            no_safe_interval='No production threshold; retain .65 only as explicitly non-production diagnostic replay. Stop without revising formula.',
            background_explosion_review='>=1000 background edges or likely-false/duplicate/hot tail at all-positive threshold => review/fail; unlabeled background never treated as verified negatives')))
    if read(OUT/'historical_start_verification.json')['status']!='PASS': raise ValueError('history_not_prepared')

def freeze():
    from app.services.storage import restore_config
    from app.config import read_yaml
    from app.utils.stable_id import content_digest
    from app.correlation.formula_v5 import SEMANTICS_VERSION,SEMANTICS_IMPLEMENTATION
    if (OUT/'formula_freeze.json').exists(): raise ValueError('immutable_formula_freeze_exists')
    if read(OUT/'historical_start_verification.json')['status']!='PASS': raise ValueError('history_not_prepared')
    original=read(BASELINE/'preparation.json');snap=original['algorithm']
    snap['implementation_version']=SEMANTICS_IMPLEMENTATION
    snap['score']['evidence_v5']=read_yaml(ROOT/'configs/algorithm-v5-evidence-semantics.yaml')['score']['evidence_v5']
    config=restore_config(snap);effective=dict(algorithm=config.snapshot,sources=original['sources'])
    files={p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'backend/app').rglob('*.py')}
    files['configs/algorithm-v5-evidence-semantics.yaml']=sha(ROOT/'configs/algorithm-v5-evidence-semantics.yaml')
    formula_files={k:v for k,v in files.items() if k in ('backend/app/correlation/formula_v5.py','backend/app/correlation/evidence_v5.py','backend/app/correlation/evidence_semantics.py')}
    save(OUT/'formula_freeze.json',dict(algorithm_version=SEMANTICS_VERSION,implementation_version=SEMANTICS_IMPLEMENTATION,
        formula_hash=content_digest(dict(files=formula_files,policy=config.snapshot['score']['evidence_v5'],semantics_sha256=sha(OUT/'evidence_semantics_matrix.json'))),
        implementation_hash=content_digest(files),config_hash=content_digest(effective),mapping_digest=config.mapping_digest,
        effective=effective,implementation_files=files,expected_candidate_digest=read(ROOT/'outputs/v5_formula_repair_integration/score_seal.json')['candidate_digest'],
        canonical_inputs={str(BASELINE/'blind'/n):sha(BASELINE/'blind'/n) for n in ('canonical.jsonl.gz','dedupe.jsonl.gz','entities.jsonl.gz')},
        weights_changed=False,formula_revision_count=1,thresholds_unfrozen=True,semantics_sha256=sha(OUT/'evidence_semantics_matrix.json')))
    print('SEMANTICS_FORMULA_FROZEN',flush=True)

def verify_freeze():
    frozen=read(OUT/'formula_freeze.json')
    for name,digest in frozen['implementation_files'].items():
        if sha(ROOT/name)!=digest: raise ValueError('formula_source_changed:'+name)
    if sha(OUT/'evidence_semantics_matrix.json')!=frozen['semantics_sha256']: raise ValueError('semantics_changed')
    for name,digest in frozen['canonical_inputs'].items():
        if sha(Path(name))!=digest: raise ValueError('canonical_changed:'+name)
    return frozen

def runtime_adapter():
    from evaluation.framework.formula_repair import runtime
    from app.correlation import evidence_semantics
    runtime.OUT=OUT
    runtime.verify_freeze=verify_freeze
    return runtime

def blind():
    runtime_adapter().blind()

def verify_seal(): return runtime_adapter().verify_seal()

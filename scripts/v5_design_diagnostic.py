"""Diagnostic-only v5 experiments. Never publishes domain objects or changes v4.

Production supplies observations, reliability, candidate admission and penalties.
Only this module interprets evidence states and compares hypothetical policies.
All transformations operate on deep-copied diagnostic dictionaries, not alerts.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import asdict
import hashlib
import heapq
import json
import math
from pathlib import Path
import random
import sys
import time

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'scripts'))
from app.adapters.base import AdapterSettings
from app.adapters.cptc import load_cptc_dataset, read_cptc_file
from app.adapters.suricata import SuricataAdapter
from app.correlation.candidates import generate_candidates
from app.correlation.edges import correlation_version
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import deduplicate
from app.entities.extraction import extract_entities
from app.models.base import resolve_pointer
from app.services.storage import file_digest
from app.services.capacity import bounded_execution
from app.utils.stable_id import content_digest
from cptc_2018_step3a import atomic_json, load_frozen_config
from cptc_top100_diagnostic import TopK
from demo_support import truth_guard

OUT = ROOT / 'outputs/v5_design_diagnostic'
DEV = ROOT / 'data/cptc_2018/dev/suricata_alert_t5_dev_10k.json.gz'
RAW = ROOT / 'data/cptc_2018/raw/suricata/suricata_alert_t5.json.gz'
VERSION = 'v5-design-diagnostic-1'
FAMILIES = ('time', 'entity', 'relation', 'behavior', 'source')
STATES = ('SUPPORTED', 'CONTRADICTED', 'UNOBSERVABLE', 'UNKNOWN', 'NOT_APPLICABLE')
CUTS = (.40, .50, .60, .65, .70, .80)
CANDIDATES = ('a', 'b', 'c', 'd')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def log(stage, **data):
    print(json.dumps(dict(stage=stage, **data), ensure_ascii=False), flush=True)


def design():
    """Write before looking at v5 outcomes; no signature-specific parameters."""
    return dict(version=VERSION, seed=42, reference_threshold=.65,
        family_weights='unchanged frozen v4 positive family weights',
        minimum_supported_mass=.25, sufficient_supported_mass=.50,
        minimum_confidence=.60, minimum_independent_families=2, quorum=3,
        temporal_support_minimum=.50, contradiction_factor=.45,
        negative_control_pairs=2000, counterfactual_pairs=100,
        primary_policy='reuse frozen v4 non-hot primary evidence; no promotion of IP/metadata',
        unknown_policy='not positive; excluded from agreement denominator; no confidence credit',
        unavailable_policy='excluded from agreement denominator; no sufficiency credit',
        dependency_groups={'TEMPORAL':'time', 'RULE_METADATA':'metadata',
            'ENTITY_IDENTITY':'identity', 'HOST_CONTEXT':'identity',
            'ACCOUNT_CONTEXT':'identity', 'PROCESS_CONTEXT':'identity',
            'RESOURCE_CONTEXT':'resource', 'NETWORK_FLOW':'identity',
            'BEHAVIOR_SEMANTIC':'propagation', 'SOURCE_CONTEXT':'source'},
        formulas={'a':'Q - frozen_penalties; primary + mass + independent-family gate',
            'b':'Q - frozen_penalties; A gates AND confidence >= C',
            'c':'Q * confidence - contradiction_factor * mismatch_mass - frozen_penalties; A gates',
            'd':'Q - frozen_penalties; A gates AND independent-family quorum'},
        definitions={'Q':'supported_weight / observable_weight; contradiction stays in denominator',
            'confidence':'min(1, supported_mass / sufficient_supported_mass); supported_mass sums family-weighted capped primitive positive mass without re-normalizing missing dimensions; not probability',
            'coverage':'observable_weight / all_configured_positive_weight; descriptive, not a hard single-source veto',
            'mismatch_mass':'family-weighted fraction of contradicted observable dimensions',
            'independence':'field dependency groups, not a statistical independence claim; metadata never votes'},
        selection_policy='compare predeclared architectures on safety/separation; no outcome-based tuning',
        scope='development only; no labels, no production edges, no clustering or chain run')


def quantiles(values):
    values = sorted(values)
    def q(f):
        if not values:
            return None
        pos = (len(values)-1)*f
        lo = int(pos)
        return values[lo]+(values[min(lo+1, len(values)-1)]-values[lo])*(pos-lo)
    return {k:q(f) for k,f in [('P50',.5),('P90',.9),('P95',.95),('P99',.99),('P99.9',.999),('max',1)]}


def distribution(rows):
    values = [r['score'] for r in rows]
    return dict(count=len(rows), quantiles=quantiles(values),
        counts_ge={str(c):sum(v>=c for v in values) for c in CUTS},
        admitted=sum(r['admitted'] for r in rows),
        high_score_rejected_by_gate=sum(r['score']>=.65 and not r['admitted'] for r in rows),
        confidence=quantiles([r['confidence'] for r in rows]))


def state_projection(pair, scorer):
    """Retain every mapped dimension. Non-pivot is not a contradiction of correlation.

    A different positive assertion needs an actual refutation; no scoped bridge,
    unknown category, and an unlisted behavior transition do not supply one.
    Entity mismatches remain observable disagreement, with their original weight.
    """
    audit = pair.diagnostics['evidence_v2']
    ds = deepcopy(audit['dimensions'])
    for d in ds:
        old = d['state']
        d['v4_state'] = old
        d['state'] = {'AVAILABLE_MATCH':'SUPPORTED', 'AVAILABLE_MISMATCH':'CONTRADICTED',
                      'UNAVAILABLE':'UNOBSERVABLE', 'NOT_APPLICABLE':'UNOBSERVABLE'}[old]
        d['basis'] = 'existing mapped evidence observation'
        if old == 'NOT_APPLICABLE':
            d['basis'] = 'both entity types absent or consumed; source capability not attested'
        if d['dimension']=='topology.network_continuity' and not d['strength']:
            d['state'] = 'UNKNOWN' if old.startswith('AVAILABLE') else 'UNOBSERVABLE'
            d['basis'] = 'no positive pivot proof is not negative proof of unordered correlation: '+audit['network_diagnostic']
        if d['dimension']=='topology.attested_relation' and not d['strength']:
            d['state']='UNKNOWN' if old.startswith('AVAILABLE') else 'UNOBSERVABLE'
            d['basis']='absent or refused attestation is not a fabricated propagation contradiction'
        if d['family']=='behavior' and not d['strength'] and old.startswith('AVAILABLE'):
            d['state']='UNKNOWN'
            d['basis']='different detector identifiers do not refute compatibility'
    hard = pair.diagnostics['conflicts']['hard']
    return dict(dimensions=ds, facts=deepcopy(audit['evidence']),
        reliability=[{**deepcopy(r),'type':scorer.index.entities[r['entity_id']].type.value,
            'evidence_refs':[dict(alert_id=aid,pointer=o.raw_pointer,side='shared')
                for aid in (pair.source_member_id,pair.target_member_id)
                for o in scorer.index.alerts[aid].entity_occurrences if o.entity_id==r['entity_id']]}
                     for r in audit['entity_reliability']], weights=audit['family_weights'],
        source_entity_ids=[[o.entity_id for o in scorer.index.alerts[aid].entity_occurrences if o.role.value=='src_ip']
                           for aid in (pair.source_member_id,pair.target_member_id)],
        conflict=pair.values['conflict'], duplicate=pair.values['duplicate'],
        penalty=scorer.algorithm.score.weights.conflict*pair.values['conflict']+
                scorer.algorithm.score.weights.duplicate*pair.values['duplicate'],
        hard=list(hard), duplicate_risk=audit['duplicate_observation_risk'],
        v4_score=pair.score, v4_valid=pair.valid, v4_audit={k:audit[k] for k in (
            'available_weight','matched_weight','normalized_quality','evidence_mass','family_strengths',
            'gate_reason','evidence_gate_passed','network_diagnostic')},
        pair=[pair.source_member_id,pair.target_member_id],
        time_gap=pair.diagnostics['gap_seconds'], half_life=pair.diagnostics['half_life_seconds'])


def summarize(view, policy):
    ds = view['dimensions']
    strengths, available, mismatch = {}, {}, {}
    for f in FAMILIES:
        obs=[d for d in ds if d['family']==f and d['state'] in ('SUPPORTED','CONTRADICTED')]
        den=math.fsum(d['weight'] for d in obs)
        strengths[f]=(max((d['strength'] for d in obs),default=0.) if f=='relation' else
            math.fsum(d['strength']*d['weight'] for d in obs)/den if den else 0.)
        available[f]=bool(den)
        mismatch[f]=math.fsum(d['weight'] for d in obs if d['state']=='CONTRADICTED')/den if den else 0.
    aw=math.fsum(view['weights'][f] for f in FAMILIES if available[f])
    mw=math.fsum(view['weights'][f]*strengths[f] for f in FAMILIES)
    relation=mw/aw if aw else 0.
    # Sufficiency uses absolute primitive mass. A family mean can rise when a
    # low-strength observation is masked; using it for confidence would reward
    # missingness. Capped positive mass is monotone under every field deletion.
    mass=math.fsum(view['weights'][f]*min(1.,math.fsum(d['weight']*d['strength']
        for d in ds if d['family']==f and d['state']=='SUPPORTED')) for f in FAMILIES)
    confidence=min(1.,mass/policy['sufficient_supported_mass'])
    coverage=aw/math.fsum(view['weights'].values())
    active={d['dimension'] for d in ds if d['state']=='SUPPORTED' and d['strength']>0}
    facts=[f for f in view['facts'] if f['dimension'] in active]
    primary=sorted(f['fact_key'] for f in facts if f['role']=='primary')
    groups=sorted({policy['dependency_groups'][f['family']] for f in facts if f['family']!='RULE_METADATA'})
    reasons=[]
    if view['hard']: reasons.append('frozen_hard_guard')
    if view['duplicate_risk']: reasons.append('duplicate_observation')
    if not primary: reasons.append('no_frozen_primary_evidence')
    if mass<policy['minimum_supported_mass']: reasons.append('minimum_supported_mass')
    if len(groups)<policy['minimum_independent_families']: reasons.append('minimum_dependency_groups')
    if strengths['time']<policy['temporal_support_minimum']: reasons.append('insufficient_temporal_support')
    mismatch_mass=math.fsum(view['weights'][f]*mismatch[f] for f in FAMILIES)
    return dict(relation_score=relation,confidence=confidence,coverage=coverage,
        supported_weight=mw,supported_mass=mass,observable_weight=aw,mismatch_mass=mismatch_mass,
        primary=primary,independent_groups=groups,gate_reasons=reasons,
        family_strengths=strengths)


def compare(view, policy):
    s=summarize(view,policy)
    results={}
    for key in CANDIDATES:
        reasons=list(s['gate_reasons'])
        value=s['relation_score']-view['penalty']
        if key=='b' and s['confidence']<policy['minimum_confidence']:
            reasons.append('minimum_confidence')
        if key=='c':
            value=s['relation_score']*s['confidence']-policy['contradiction_factor']*s['mismatch_mass']-view['penalty']
        if key=='d' and len(s['independent_groups'])<policy['quorum']:
            reasons.append('family_quorum')
        value=max(0.,min(1.,value))
        results[key]=dict(**s, score=value,admitted=value>=policy['reference_threshold'] and not reasons,
            admission_reasons=reasons+(['below_reference_threshold'] if value<policy['reference_threshold'] else []))
    return results


def time_copy(view, gap, max_window):
    v=deepcopy(view)
    v['time_gap']=gap
    t=math.exp(-math.log(2)*gap/v['half_life'])
    for d in v['dimensions']:
        if d['family']=='time':
            d.update(strength=t,state='CONTRADICTED' if gap>max_window else 'SUPPORTED',
                     basis='diagnostic timestamp permutation; original records unchanged')
    # No relation assertion survives a changed chronology without revalidation.
    for d in v['dimensions']:
        if d['family']=='relation' and d['state']=='SUPPORTED':
            d.update(strength=0.,state='UNKNOWN',basis='chronology changed; propagation not re-attested')
    return v


def mask_copy(view, mask):
    v=deepcopy(view)
    changed=[]
    names={'host':{'entity.HOST'},'account':{'entity.ACCOUNT'},
           'process':{'entity.PROCESS','topology.attested_relation'},
           'destination':{'topology.network_continuity'},
           'transport':{'topology.network_continuity'},
           'behavior_metadata':{'metadata.detector_identity'},
           'time_only':{d['dimension'] for d in v['dimensions'] if d['family']!='time'}}[mask]
    if mask=='destination':
        # Remove destination-derived shared IP only. Keep independent source IP.
        rel=[r for r in v['reliability'] if r.get('type')=='IP' and r['role_factor']!=1.]
        ids={r['entity_id'] for r in rel}
        names|={d['dimension'] for d in v['dimensions'] if d['dimension']=='entity.IP' and set(d['entity_ids'])<=ids}
        # A destination contribution may have been the per-type maximum while
        # a weaker source-IP match also exists. Keep that surviving observation.
        shared_source=set.intersection(*(set(s) for s in v.get('source_entity_ids',[[],[]])))
        remaining=[r for r in v['reliability'] if r.get('type')=='IP' and r['entity_id'] in shared_source]
        if remaining:
            for d in v['dimensions']:
                if d['dimension']=='entity.IP' and d['dimension'] in names:
                    best=min(remaining,key=lambda r:(-r['reliability'],r['entity_id']))
                    d.update(state='SUPPORTED',strength=best['reliability'],entity_ids=[best['entity_id']],
                             basis='destination masked; surviving scoped source-IP support')
                    names.remove(d['dimension'])
                    changed.append('entity.IP.destination_component')
                    for f in v['facts']:
                        if f['dimension']=='entity.IP':f.update(fact_key='entity:'+best['entity_id'],
                            entity_ids=[best['entity_id']],strength=best['reliability'],evidence_refs=best['evidence_refs'])
        elif all(v.get('source_entity_ids',[[],[]])):
            for d in v['dimensions']:
                if d['dimension']=='entity.IP' and d['dimension'] in names:
                    d.update(state='CONTRADICTED',strength=0.,entity_ids=[],
                             basis='destination masked; remaining observed source IPs differ')
                    names.remove(d['dimension'])
                    changed.append('entity.IP.destination_component')
    for d in v['dimensions']:
        if d['dimension'] in names:
            if d['state']=='SUPPORTED': changed.append(d['dimension'])
            d.update(state='UNOBSERVABLE',strength=0.,basis='diagnostic counterfactual mask')
    # Removing evidence cannot remove an already observed contradiction/duplicate
    # penalty in these controlled ablations. No masked value becomes a match.
    return v,changed


def alert_detail(a):
    return {k:getattr(a,k).value if hasattr(getattr(a,k),'value') else getattr(a,k)
            for k in ('alert_id','timestamp','source_type','source_namespace','sensor','src_ip','dst_ip',
                      'src_port','dst_port','signature','rule_id','category')} | {
        'timestamp':str(a.timestamp), 'signature_id':a.raw_alert.get('alert',{}).get('signature_id')}


def expand(view, results, scorer):
    a,b=(scorer.index.alerts[i] for i in view['pair'])
    return dict(alert_a=alert_detail(a),alert_b=alert_detail(b),
        relation_families=sorted({f['family'] for f in view['facts']}),
        evidence_state={s:[d for d in view['dimensions'] if d['state']==s] for s in STATES},
        evidence_refs=view['facts'], v4_score=view['v4_score'],v4_audit=view['v4_audit'],
        candidates=results,penalty=view['penalty'],
        explanation='Mapped positive observations form supported_weight; contradicted dimensions remain in '
            'observable capacity; unavailable/unknown dimensions add neither agreement nor confidence. '
            'Primary evidence and dependency groups are counted separately from normalized score.')


def load_development():
    config,receipt,path=load_frozen_config()
    saved=read(ROOT/'outputs/cptc_2018_step3a_t5/recipe.json')
    settings={k:AdapterSettings(**v) for k,v in saved['config_snapshot']['sources'].items()}
    ingestion=load_cptc_dataset(ROOT).config
    adapter=SuricataAdapter(ingestion,next(iter(settings.values())))
    alerts=[]
    for record in read_cptc_file(DEV):
        if record.error: raise ValueError(record.error)
        alerts.append(adapter.convert(record.eve))
    if len(alerts)!=10000: raise ValueError('development_count_changed')
    raw_identity=content_digest(sorted([a.alert_id,a.raw_fingerprint] for a in alerts))
    log('dedupe_start',alerts=len(alerts))
    groups=deduplicate(alerts,config,settings).groups
    extracted=extract_entities(alerts,settings)
    index=AlertIndex(extracted.alerts,groups,extracted.entities)
    scorer=CorrelationScorer(index,config,settings,saved['config_hash'])
    return scorer,saved,raw_identity,groups


def inventory(scorer):
    counts=Counter()
    for a in scorer.index.alerts.values():
        for f in ('host','account','session','process','parent_process','url','domain','src_ip','dst_ip',
                  'src_port','dst_port','signature','rule_id'):
            counts[f]+=getattr(a,f) is not None
        counts['mapped_category']+=a.category.value!='unknown'
        counts['attested_relation']+=bool(a.relations)
        counts['flow_id']+=a.raw_alert.get('flow_id') is not None
        counts['protocol']+=a.raw_alert.get('proto') is not None
    return dict(observed_field_counts=dict(counts),
        recommended_profile='versioned adapter/deployment capability declaration with provenance; not dataset-name rules',
        distinguish=['source cannot observe','field omitted on this record','extraction unsupported','not applicable to proposed relation'],
        source_observations='These are empirical t5 counts, not product-wide Suricata capability claims.',
        limitation='CanonicalAlert lacks attested capability/field-absence reason. Absent host/process/account cannot '
                   'prove global source inability. No adapter or schema change in this task.',
        wazuh='Existing parsed fields vary by rule/input profile; no new Wazuh capability experiment here.',
        same_source_policy='No cross-source prerequisite; independence bonus still requires frozen attestation.')


def freeze_check():
    before=read(OUT/'protected_before.json')
    after={p:file_digest(ROOT/p) if (ROOT/p).is_file() else None for p in before}
    changes={p:dict(before=before[p],after=after[p]) for p in before if before[p]!=after[p]}
    result=dict(status='PASS' if not changes else 'FAIL',protected_files_changed=bool(changes),
        changed=changes,protected_count=len(before),before=before,after=after,
        raw_unchanged=before[RAW.relative_to(ROOT).as_posix()]==after[RAW.relative_to(ROOT).as_posix()],
        development_unchanged=before[DEV.relative_to(ROOT).as_posix()]==after[DEV.relative_to(ROOT).as_posix()],
        git_status='unavailable_no_git_metadata')
    atomic_json(OUT/'freeze_verification.json',result)
    if changes: raise ValueError('protected_files_changed')
    return result


def validate_refs(row,scorer):
    ids=set(row['pair'])
    for f in row['facts']:
        for ref in f['evidence_refs']:
            if ref['alert_id'] not in ids: raise ValueError('reference_outside_pair')
            resolve_pointer(scorer.index.alerts[ref['alert_id']].raw_alert,ref['pointer'])


def run():
    OUT.mkdir(exist_ok=True)
    if not (OUT/'protected_before.json').exists():
        raise ValueError('capture_pre_task_protected_hashes_first')
    policy=design()
    policy_path=OUT/'diagnostic_policy.yaml'
    if policy_path.exists():
        if yaml.safe_load(policy_path.read_text(encoding='utf8'))!=policy:
            raise ValueError('predeclared_policy_changed')
    else: policy_path.write_text(yaml.safe_dump(policy,allow_unicode=True,sort_keys=True),encoding='utf8')
    policy=yaml.safe_load(policy_path.read_text(encoding='utf8'))
    started=time.perf_counter()
    with truth_guard(ROOT),bounded_execution(OUT/'spill') as spill:
        spill.progress=lambda row:log(**row)
        scorer,recipe,dataset_digest,dedupe_groups=load_development()
        cfg=scorer.algorithm
        log('candidate_generation_start',representatives=scorer.index.N)
        candidates=generate_candidates(scorer.index,scorer.config,scorer)
        if candidates.resource_truncated_count: raise ValueError('candidate_resource_truncated')
        log('candidate_generation_complete',count=len(candidates.pairs))
        # Persist only tiny numeric rows and the exact frozen candidate identity stream.
        rows={k:[] for k in CANDIDATES}
        tops={k:TopK(100) for k in CANDIDATES}
        v4scores=[]; matrix=defaultdict(Counter); supported=Counter(); v4family=Counter()
        reservoir=[]; rng=random.Random(policy['seed']); digest=hashlib.sha256()
        candidate_digest=hashlib.sha256(); member_count=0;primary_count=0
        with (OUT/'candidate_pairs.jsonl').open('w',encoding='utf8',newline='\n') as stream:
            for n,c in enumerate(candidates.pairs,1):
                text=json.dumps(asdict(c),sort_keys=True,separators=(',',':'),ensure_ascii=False)
                candidate_digest.update((text+'\n').encode());stream.write(text+'\n')
                # Preserve complete member evaluation and choose a whole pair for each policy.
                left,right=c.support_key
                best={k:None for k in CANDIDATES}; fallback={k:None for k in CANDIDATES}
                members=[]
                for a in scorer.index.groups[left]:
                    for b in scorer.index.groups[right]:
                        pair=scorer.score_pair(a,b);member_count+=1
                        view=state_projection(pair,scorer); results=compare(view,policy)
                        members.append((pair,view,results))
                        for k,r in results.items():
                            rank=(-r['score'],scorer.index.times[a],scorer.index.times[b],a,b)
                            record=(rank,a,b,r)
                            if fallback[k] is None or rank<fallback[k][0]:fallback[k]=record
                            if not r['gate_reasons'] and not r['admission_reasons'] and (best[k] is None or rank<best[k][0]):best[k]=record
                for k in CANDIDATES:
                    rank,a,b,r=fallback[k]
                    rows[k].append(dict(score=r['score'],confidence=r['confidence'],admitted=best[k] is not None))
                    # Global Top100 score inspection uses the max numerical whole-member pair,
                    # even if a different valid member would be admitted.
                    rawbest=fallback[k]
                    tops[k].add(rawbest[3]['score'],rawbest[1],rawbest[2],{'candidate':n})
                # Evidence inventory is explicitly member-pair based, not a fabricated combined group.
                for pair,view,results in members:
                    v4scores.append(pair.score)
                    for d in view['dimensions']:matrix[d['dimension']][d['state']]+=1
                    supported[min(4,len(summarize(view,policy)['independent_groups']))]+=1
                    primary_count+=bool(results['a']['primary'])
                    v4family.update(pair.diagnostics['evidence_v2']['evidence_families'])
                    digest.update(json.dumps([view['pair'],results],sort_keys=True,separators=(',',':')).encode())
                    item=(pair.source_member_id,pair.target_member_id)
                    if len(reservoir)<policy['negative_control_pairs']:reservoir.append(item)
                    else:
                        j=rng.randrange(member_count)
                        if j<len(reservoir):reservoir[j]=item
                if n%5000==0:log('scoring',candidates=n,members=member_count,seconds=round(time.perf_counter()-started,1))
        # Candidate order/provenance replay on reversed inputs, independent of score results.
        idx=scorer.index
        reverse=AlertIndex(list(reversed(list(idx.alerts.values()))),list(reversed(dedupe_groups)),list(reversed(list(idx.entities.values()))))
        reverse_scorer=CorrelationScorer(reverse,scorer.config,scorer.settings,scorer.config_hash)
        again=generate_candidates(reverse,scorer.config,reverse_scorer)
        hd=hashlib.sha256()
        for c in again.pairs:hd.update((json.dumps(asdict(c),sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode())
        if hd.hexdigest()!=candidate_digest.hexdigest():raise ValueError('candidate_replay_mismatch')
        del reverse_scorer,reverse,again
        log('scoring_complete',candidates=len(candidates.pairs),members=member_count)
        top_rows={}; views={}
        for k in CANDIDATES:
            top_rows[k]=[]
            for row in tops[k].rows():
                ids=(row['alert_a_id'],row['alert_b_id'])
                if ids not in views:views[ids]=state_projection(scorer.score_pair(*ids),scorer)
                view=views[ids];validate_refs(view,scorer)
                top_rows[k].append(expand(view,compare(view,policy),scorer))
        atomic_json(OUT/'top_pairs.json',top_rows)
        capability=inventory(scorer);atomic_json(OUT/'source_capability_analysis.json',capability)
        atomic_json(OUT/'evidence_family_inventory.json',dict(
            states=STATES,evidence_state_matrix={k:dict(v) for k,v in sorted(matrix.items())},
            dimensions_retained='all frozen v4 dimensions; destination/transport additionally audited below',
            evidence_dependency_groups=policy['dependency_groups'],
            support_family_counts={str(i) if i<4 else '4+':supported[i] for i in range(5)},
            count_unit='complete member pairs of frozen admitted candidates; dependency groups exclude metadata',
            primary_pairs=primary_count,v4_fact_family_counts=dict(v4family),
            relation_mapping_role='produce field-backed observations and dependencies; scoring and admission separate',
            additional_context={'destination':'frozen target/conflict and entity roles retained; not another independent vote',
                'transport':'frozen flow/protocol observation identity retained; not an extra vote on the same endpoint evidence'}))
        dist={k:distribution(rows[k]) for k in CANDIDATES}
        atomic_json(OUT/'score_distribution.json',dist)
        controls=negative_controls(scorer,reservoir,policy)
        atomic_json(OUT/'negative_controls.json',controls)
        masks=counterfactuals(scorer,views,policy)
        atomic_json(OUT/'counterfactual_missing_evidence.json',masks)
        reach={k:dict(theoretical_maximum=1.,theoretical_kind='unpenalized score supremum; gates additionally required',
            dataset_reachable_maximum=max(r['score'] for r in rows[k]),
            dataset_reachable_scope='exact over complete frozen admitted candidate/member universe on development set; global all-pairs bounds separately reported',
            observed_maximum=dist[k]['quantiles']['max'],**dist[k]) for k in CANDIDATES}
        for k in CANDIDATES:atomic_json(OUT/f'candidate_{k}_results.json',dict(candidate=k,formula=policy['formulas'][k],**reach[k]))
        atomic_json(OUT/'score_reachability.json',reach)
        history=read(ROOT/'outputs/cptc_t5_correlation_v4_diagnostic_12/score_reachability.json')
        decomposition=dict(historical_full_t5=dict(theoretical_maximum=history['CONFIG_THEORETICAL_MAX'],
            dataset_reachable_maximum=history['DATASET_REACHABLE_MAX'],observed_maximum=history['OBSERVED_MAX'],
            evidence_path='outputs/cptc_t5_correlation_v4_diagnostic_12/score_reachability.json'),
            development_10k=dict(observed=quantiles(v4scores),scored_member_pairs=member_count),
            formula='clamp(.65*MW/AW + .35*MW/TW - .45*C - .40*D,0,1)',
            diagnosis='v4 already normalizes unavailable evidence for quality. Fixed total-configured mass and '
                'available-zero topology retain reachability constraints. Zero pivot support is not a proven contradiction '
                'of undirected correlation. Metadata cap, role attenuation and empirical reliability also limit positives.',
            distinction={'missing':'UNAVAILABLE/NOT_APPLICABLE do not enter quality AW, but earn no fixed mass',
                'mismatch':'explicit observed disagreement stays in denominator; some old mismatch means unsupported hypothesis',
                'denominator':'normal complete-network AW=.90 includes .36 zero topology; changing that to unknown makes AW=.54',
                'weight':'.36 topology vs .04 capped metadata reflects propagation-heavy allocation; not only a threshold issue',
                'insufficient_positive':'IP roles/reliability and metadata cap remain conservative; sparse pairs still need primary proof'},
            historical_witness=history['dataset_max_certificate']['witness'])
        atomic_json(OUT/'v4_failure_decomposition.json',decomposition)
        recommendation=dict(task_result='V5_DESIGN_PROMISING_BUT_NEEDS_MORE_EVIDENCE',
            recommendation='Do not implement v5 yet',
            architecture=['Evidence observations','State with explicit hypothesis/absence reason','Relation strength',
                          'Evidence sufficiency and coverage','Dependency-aware safety gate','Admission'],
            favored_for_further_validation='B architecture with explicit contradictions and D dependency audit; no final formula frozen',
            reason='One nearly complete Suricata development source cannot validate source capability, real sparse records, '
                'cross-source behavior or pair correctness. Negative controls are stress probes, not pair ground truth.',
            no_production_changes=True,threshold_semantics='new .65 is normalized agreement or coverage-adjusted agreement, not old quality+mass score; not directly comparable',
            required_next_evidence=['independent unlabeled development scenarios with real sparse/medium records',
                'declared versioned capability profiles and missingness reasons',
                'human-reviewed pair sample/independent evaluation split; retain all negative results'])
        atomic_json(OUT/'recommended_v5_architecture.json',recommendation)
        freeze_check()
        manifest=dict(version=VERSION,seed=policy['seed'],dataset_sha256=file_digest(DEV),raw_sha256=file_digest(RAW),
            dataset_digest=dataset_digest,config_hash=scorer.config_hash,base_config_hash=scorer.config.config_hash,
            mapping_digest=recipe['mapping_digest'],algorithm_version=correlation_version(scorer.config),
            diagnostic_code_hash=file_digest(Path(__file__)),diagnostic_policy_hash=file_digest(policy_path),
            policy_digest=content_digest(policy),input_count=len(idx.alerts),representative_count=idx.N,
            candidate_count=len(candidates.pairs),scored_candidate_count=len(candidates.pairs),scored_member_count=member_count,
            candidate_identity_digest=candidate_digest.hexdigest(),reverse_candidate_replay_equal=True,
            candidate_resource_truncated_count=candidates.resource_truncated_count,
            candidate_policy_pruned_count=candidates.policy_pruned_count,
            semantic_results_digest=digest.hexdigest(),threshold=.65,clustering_chain_threshold=.70,
            production_edge_count='N/A diagnostic only',incident_count='N/A',chain_edge_count='N/A',
            runtime_seconds=time.perf_counter()-started,task_result=recommendation['task_result'],
            known_limitations=['No pair-level ground truth or precision/recall','Real sparse=0, medium=4',
                'Global all-pair v5 maximum requires independent certificate; candidate-scope exact maximum explicitly delimited',
                'Capability unknown is never asserted as vendor-wide inability'],
            files={p.name:file_digest(p) for p in sorted(OUT.iterdir()) if p.is_file() and p.name not in ('manifest.json','execution.log')})
        atomic_json(OUT/'manifest.json',manifest)
        log('complete',result=recommendation['task_result'],counts={k:dist[k]['admitted'] for k in CANDIDATES},
            seconds=round(manifest['runtime_seconds'],1))


def negative_controls(scorer,pairs,policy):
    rng=random.Random(policy['seed']+1)
    original=[state_projection(scorer.score_pair(*p),scorer) for p in pairs]
    ids=sorted(scorer.index.alerts); shuffled=ids[:];rng.shuffle(shuffled)
    perm=dict(zip(ids,shuffled)); times=[scorer.index.times[i]/1e6 for i in ids]
    rng.shuffle(times);timeperm=dict(zip(ids,times))
    populations={name:{k:[] for k in CANDIDATES} for name in (
        'paired_original','time_shuffle','entity_permutation','cross_window_random','signature_only')}
    samples=defaultdict(list); manipulation=Counter()
    max_window=scorer.algorithm.candidate.max_window_seconds
    def add(name,v):
        rs=compare(v,policy)
        for k,r in rs.items():populations[name][k].append(r)
        if len(samples[name])<5:samples[name].append(dict(pair=v['pair'],time_gap=v['time_gap'],results=rs,
            transformation=v.get('transformation','none')))
    for n,v in enumerate(original):
        add('paired_original',v)
        a,b=v['pair'];gap=abs(timeperm[a]-timeperm[b])
        add('time_shuffle',time_copy(v,gap,max_window))
        donor=state_projection(scorer.score_pair(perm[a],perm[b]),scorer)
        nv=deepcopy(v)
        # Permute the complete endpoint/resource bundle at alert level, preserving
        # internal scoped identities, transport and context. Detector/time stay.
        nv['dimensions']=[d for d in nv['dimensions'] if d['family'] not in ('entity','relation')]+[
            deepcopy(d) for d in donor['dimensions'] if d['family'] in ('entity','relation')]
        nv['facts']=[f for f in nv['facts'] if f['dimension'].startswith(('time.','metadata.','context.'))]+[
            deepcopy(f) for f in donor['facts'] if f['dimension'].startswith(('entity.','topology.'))]
        nv['penalty']=donor['penalty'];nv['hard']=donor['hard'];nv['duplicate_risk']=donor['duplicate_risk']
        nv['transformation']=dict(entity_bundle_donors=[perm[a],perm[b]],record_level=True,
            note='evidence projection control; no CanonicalAlert/raw mutation; refs retain donor IDs')
        manipulation['entity_primary_survived']+=bool(summarize(nv,policy)['primary'])
        manipulation['original_primary']+=bool(summarize(v,policy)['primary'])
        add('entity_permutation',nv)
        # Rank-separated halves avoid rejection sampling bias and ensure genuine far windows.
        ordered=sorted(ids,key=lambda i:(scorer.index.times[i],i)) if n==0 else ordered
        ia=ordered[rng.randrange(max(1,len(ids)//4))]
        ib=ordered[len(ids)*3//4+rng.randrange(len(ids)-len(ids)*3//4)]
        far=state_projection(scorer.score_pair(ia,ib),scorer)
        if far['time_gap']<=max_window:raise ValueError('cross_window_control_not_far')
        far=time_copy(far,far['time_gap'],max_window)
        add('cross_window_random',far)
        # Same detector/signature, deliberately remove all entity and propagation
        # observations. This is a controlled insufficiency probe, not a real attack.
        sig=deepcopy(v)
        for d in sig['dimensions']:
            if d['family'] not in ('time','behavior'):d.update(state='UNOBSERVABLE',strength=0.)
            if d['family']=='behavior':d.update(state='SUPPORTED',strength=scorer.algorithm.score.evidence_v3.metadata_cap)
        sig['transformation']='counterfactual signature-only upper-strength probe (metadata cap); no attack label'
        add('signature_only',sig)
    results={name:{k:distribution(rows) for k,rows in grouped.items()} for name,grouped in populations.items()}
    return dict(populations=results,examples=dict(samples),manipulation_checks=dict(manipulation),
        design='Same seeded sampled original population for paired shuffles. No candidate regeneration after perturbation; fixed-pair score stress test.',
        sample_count=len(pairs),seed=policy['seed']+1,
        limitations=['Shuffled pairs can accidentally preserve valid contexts; not verified negatives or false-positive rate',
            'Quorum measures dependency groups, not statistical independence',
            'Signature-only control is a counterfactual insufficiency test; real signature-only pairs separately inspected in report'])


def counterfactuals(scorer,views,policy):
    chosen=sorted(views.values(),key=lambda v:(-summarize(v,policy)['supported_weight'],v['pair']))[:policy['counterfactual_pairs']]
    rows=[];checks=Counter()
    for view in chosen:
        original=compare(view,policy)
        for name in ('host','account','process','destination','transport','behavior_metadata','time_only'):
            masked,removed=mask_copy(view,name)
            result=compare(masked,policy)
            checks['operations']+=1
            checks['supported_removal']+=bool(removed)
            checks['confidence_increases']+=result['b']['confidence']>original['b']['confidence']+1e-12
            checks['time_only_admitted']+=name=='time_only' and any(r['admitted'] for r in result.values())
            rows.append(dict(pair=view['pair'],mask=name,removed_supported=removed,no_op=not removed,
                original=original,masked=result))
    return dict(rows=rows,checks=dict(checks),selected_pair_count=len(chosen),
        scope='diagnostic evidence copies only; original source and CanonicalAlert untouched',
        limitation='host/account/process already absent in t5; those masks are genuine no-ops, not validation of real host/process sparsity')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--verify-freeze',action='store_true')
    parser.add_argument('--complete-reports',action='store_true',
                        help='Certify global reachability, replay observations and sync paper from completed scoring')
    args=parser.parse_args()
    if args.verify_freeze:log('freeze',status=freeze_check()['status'])
    elif args.complete_reports:
        import runpy
        with truth_guard(ROOT),bounded_execution(OUT/'supplement_copy_spill') as spill:
            spill.progress=lambda row:log(**row)
            scorer,_,_,_=load_development()
            log('supplement_index_ready',alerts=len(scorer.index.alerts),representatives=scorer.index.N)
            probe=runpy.run_path(str(OUT/'global_reachability_probe.py'),run_name='diagnostic_bound_helper')
            atomic_json(OUT/'global_score_reachability.json',probe['certify'](scorer,design()))
            extra=runpy.run_path(str(OUT/'observation_supplement.py'),run_name='diagnostic_observation_helper')
            extra['supplement'](scorer)
            runpy.run_path(str(OUT/'control_residual_audit.py'),run_name='diagnostic_control_audit')
            renderer=runpy.run_path(str(OUT/'report_and_paper_sync.py'),run_name='diagnostic_report_helper')
            renderer['render']()
    else:run()

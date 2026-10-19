"""Expand only globally selected CPTC candidates; no scoring decisions supplied."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
import json
import math
from pathlib import Path
import sqlite3
import time

from cptc_top100_diagnostic import (ROOT, RUN, OUT, INPUT, read_json, log, frozen,
    saved_index, protected_hashes, atomic_json)
from app.adapters.cptc import read_cptc_file
from app.models.base import resolve_pointer
from app.services.storage import file_digest
from app.utils.stable_id import content_digest, raw_fingerprint, id_for
from demo_support import truth_guard


TOLERANCE = 1e-12


def jdump(value):
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)


def score_features(scored, scorer):
    """Algebraically attribute the existing v4 total, preserving all zeros.

    The relation family uses max; only a maximum dimension receives its family
    allocation (lexical first if tied). This is reporting attribution, not an
    extra scoring rule. The five family totals always use production strengths.
    """
    audit = scored.diagnostics['evidence_v2']
    qf, mf = audit['quality_factor'], audit['mass_factor']
    aw, tw = audit['available_weight'], audit['total_configured_weight']
    scale = (qf/aw if aw else 0.) + (mf/tw if tw else 0.)
    available = [d for d in audit['dimensions'] if d['state'].startswith('AVAILABLE')]
    rows, families = [], []
    for family, weight in audit['family_weights'].items():
        ds = [d for d in available if d['family'] == family]
        strength = audit['family_strengths'][family]
        quality_contribution = qf*weight*strength/aw if aw and ds else 0.
        mass_contribution = mf*weight*strength/tw if tw and ds else 0.
        families.append(dict(feature_name='family.'+family,raw_value=strength,eligible=bool(ds),
            weight=weight,quality_contribution=quality_contribution,mass_contribution=mass_contribution,
            positive_contribution=quality_contribution+mass_contribution,negative_contribution=0.,
            net_contribution=quality_contribution+mass_contribution))
        den = math.fsum(d['weight'] for d in ds)
        max_dim = min(ds, key=lambda d:(-d['strength'],d['dimension']))['dimension'] if ds else None
        for d in (d for d in audit['dimensions'] if d['family'] == family):
            eligible = d['state'].startswith('AVAILABLE')
            internal = (d['strength'] if d['dimension']==max_dim else 0.) if family=='relation' else (
                d['weight']*d['strength']/den if den and eligible else 0.)
            positive = weight*internal*scale if eligible else 0.
            evidence = [f for f in audit['evidence'] if f['dimension']==d['dimension']]
            rows.append(dict(feature_name=d['dimension'],state=d['state'],raw_value=d['strength'],
                normalized_value=internal,eligible=eligible,weight=d['weight'],family=family,
                family_weight=weight,family_available_dimension_weight=den,
                positive_contribution=positive,negative_contribution=0.,net_contribution=positive,
                evidence=evidence,entity_ids=d['entity_ids'],
                reason=('production relation-family max; deterministic reporting attribution' if family=='relation'
                        else 'production family weighted mean, then quality/mass scaling')))
    for name in ('conflict','duplicate'):
        signed = scored.contributions[name]
        rows.append(dict(feature_name='penalty.'+name,raw_value=scored.values[name],
            normalized_value=scored.values[name],eligible=True,
            weight=getattr(scorer.algorithm.score.weights,name),positive_contribution=0.,
            negative_contribution=signed,net_contribution=signed,
            evidence=scored.diagnostics['conflicts' if name=='conflict' else 'duplicate_features'],
            reason='production signed penalty; conflict combines by maximum'))
    positive = math.fsum(f['positive_contribution'] for f in families)
    penalty = -math.fsum(scored.contributions[n] for n in ('conflict','duplicate'))
    raw = positive-penalty
    feature_raw = math.fsum(f['net_contribution'] for f in rows)
    reconstructed = min(1.,max(0.,raw))
    feature_error = abs(feature_raw-raw)
    error = max(abs(reconstructed-scored.score),feature_error)
    return dict(formula='clamp(quality_factor * matched_weight / available_weight + mass_factor * matched_weight / total_configured_weight - conflict_weight*C - duplicate_weight*D,0,1)',
        features=rows,family_contributions=families,positive_score_total=positive,penalty_total=penalty,
        raw_total=raw,feature_raw_total=feature_raw,feature_reconstruction_error=feature_error,
        clamp_adjustment=reconstructed-raw,final_score=scored.score,
        reconstructed_score=reconstructed,absolute_error=error,tolerance=TOLERANCE,
        status='PASS' if error<=TOLERANCE else 'SCORE_BREAKDOWN_MISMATCH',
        normalized_quality=audit['normalized_quality'],evidence_mass=audit['evidence_mass'],
        available_weight=aw,matched_weight=audit['matched_weight'],total_configured_weight=tw,
        quality_factor=qf,mass_factor=mf,
        legacy_seven_component_audit=dict(raw_values=scored.values,signed_contributions=scored.contributions,
            sum_is_not_v4_final_score=True,signed_sum=math.fsum(scored.contributions.values())))


def rejection(scored, threshold):
    audit, conflicts = scored.diagnostics['evidence_v2'],scored.diagnostics['conflicts']
    below = scored.score < threshold
    gate = not audit['evidence_gate_passed']
    if conflicts['hard']:
        primary = 'REJECTED_BY_GUARD'
    elif gate or 'missing_non_time_support' in scored.rejection_codes:
        primary = 'REJECTED_EVIDENCE_REQUIREMENT'
    elif below:
        primary = 'REJECTED_BELOW_THRESHOLD'
    else:
        primary = 'ADMITTED_CORRELATION_EDGE'
    secondary = []
    if below and primary!='REJECTED_BELOW_THRESHOLD':
        secondary.append('REJECTED_BELOW_THRESHOLD')
    if gate and primary!='REJECTED_EVIDENCE_REQUIREMENT':
        secondary.append('REJECTED_EVIDENCE_REQUIREMENT')
    return dict(primary_rejection_reason=primary,secondary_rejection_reasons=secondary,
        production_member_valid=scored.valid,production_evidence_decision=audit['decision'],
        production_rejection_codes=scored.rejection_codes,gate_reason=audit['gate_reason'],
        threshold_passed=not below,formal_edge_admitted=scored.valid and not below,
        rejection_stage='hard_guard' if conflicts['hard'] else 'evidence_gate' if gate else 'threshold' if below else 'admitted')


def validate_refs(scored, alerts):
    refs = []
    def walk(value):
        if isinstance(value,dict):
            if {'alert_id','pointer','side'} <= value.keys():
                refs.append({k:value[k] for k in ('alert_id','pointer','side')})
            for v in value.values():
                walk(v)
        elif isinstance(value,(list,tuple)):
            for v in value:
                walk(v)
    walk(scored.diagnostics)
    for reason in scored.reasons:
        for ref in reason.params.get('raw_pointers',[]):
            assert ref['alert_id'] in reason.alert_ids, 'reason_pointer_ownership'
    walk([r.model_dump(mode='json') for r in scored.reasons])
    for alert in alerts.values():
        refs += [dict(alert_id=alert.alert_id,pointer=o.raw_pointer,side='shared') for o in alert.entity_occurrences]
        refs += [dict(alert_id=alert.alert_id,pointer=p.raw_pointer,side='shared') for p in alert.field_provenance.values()]
    unique = {tuple(r[k] for k in ('alert_id','pointer','side')):r for r in refs}
    result = []
    for _,ref in sorted(unique.items()):
        assert ref['alert_id'] in alerts, 'cross_pair_pointer'
        value = resolve_pointer(alerts[ref['alert_id']].raw_alert,ref['pointer'])
        result.append(dict(**ref,resolved_value=value,resolved=True))
    return result


def guards(scored,scorer):
    c,a = scored.diagnostics['conflicts'],scored.diagnostics['evidence_v2']
    soft = dict(c['soft'])
    result=[]
    for name in scorer.algorithm.conflict.hard_rules:
        session = name=='verified_incompatible_session'
        triggered = name in c['hard']
        result.append(dict(guard_name=name,evaluated=True,triggered=triggered,
            evidence_available=c['session_compatibility']['verified'] if session else True,
            status='NOT_EVALUABLE / NOT_TRIGGERED' if session and not triggered else 'TRIGGERED' if triggered else 'NOT_TRIGGERED',
            evidence=c['session_compatibility'] if session else dict(left_targets=c['left_targets'],right_targets=c['right_targets']),
            effect='hard_reject' if triggered else 'none'))
    for name in type(scorer.algorithm.conflict.strengths).model_fields:
        strength = soft.get(name,0.)
        result.append(dict(guard_name=name,evaluated=True,triggered=name in soft,
            evidence_available=c['session_compatibility']['verified'] if name=='incompatible_session' else True,
            evidence=c,raw_strength=strength,
            effect='soft_penalty_maximum' if strength else 'none',
            selected_in_max=bool(strength and strength==c['penalty'])))
    conditions = {
        'require_non_time_support': ('missing_non_time_support' not in scored.rejection_codes,scored.diagnostics['shared_entity_ids']),
        'minimum_evidence_mass': (a['evidence_mass']>=scorer.algorithm.score.evidence_v2.gate.minimum_mass,a['evidence_mass']),
        'primary_evidence_required': (bool(a['primary_evidence']),a['primary_evidence']),
        'duplicate_observation_protection': (not a['duplicate_observation_risk'],scored.diagnostics['duplicate_features']['observation_identity']),
        'evidence_gate': (a['evidence_gate_passed'],a['gate_reason']),
        'formal_score_threshold': (a['threshold_passed'],dict(score=scored.score,threshold=a['threshold']))}
    for name,(passed,evidence) in conditions.items():
        result.append(dict(guard_name=name,evaluated=True,triggered=not passed,
            evidence_available=True,evidence=evidence,effect='admission_reject' if not passed else 'none'))
    return result


def relationship(scored,scorer,a,b):
    matched = [r.json_data() for r in scored.relations]
    refused = scored.diagnostics['refused_relations']
    priority = scorer.algorithm.chain.relation_priority
    types = sorted({r.relation_type for r in scored.relations},key=priority.index)
    checks=[]
    for kind in priority:
        actual=[r for r in matched if r['relation_type']==kind]
        checks.append(dict(relationship_type=kind,evaluated=True,accepted=bool(actual),
            mapping_evidence=actual,upstream_attestations=[r.model_dump(mode='json') for x in (a,b) for r in x.relations if r.relation_type.value==kind],
            rejections=[r for r in refused if r['relation_type']==kind],
            reason='verified frozen field gate' if actual else 'no verified relation from frozen scorer; endpoint equality alone supplies no attestation'))
    return dict(relationship_candidates=checks,selected_relationship=types[0] if types else 'NONE',
        selected_chain_relationship=scorer.algorithm.chain.relation_type_mapping[types[0]] if types else 'NONE',
        mapping_evidence=matched,mapping_rejected=not bool(types),
        mapping_rejection_reason=None if types else 'NO_FROZEN_RELATIONSHIP',
        relation_score=scored.values['relation'],
        admission_scope='Chain mapping is downstream. Lack of mapping does not reject an otherwise valid undirected CorrelationEdge.')


def entities_for(alert,other,scorer,scored):
    idx = scorer.index
    reliability={r['entity_id']:r for r in scored.diagnostics['evidence_v2']['entity_reliability']}
    evidence={f['entity_id']:f for f in scored.diagnostics['entity_features']}
    obs=scorer.duplicate.observation.identities[alert.alert_id].observation_id
    rows=[]
    for occurrence in alert.entity_occurrences:
        eid=occurrence.entity_id
        e=idx.entities[eid]
        rel=reliability.get(eid)
        rows.append(dict(entity_id=eid,entity_type=e.type.value,scope=e.scope,
            normalized_value=e.value,raw_value=resolve_pointer(alert.raw_alert,occurrence.raw_pointer),
            role=occurrence.role.value,role_source=alert.field_provenance.get(occurrence.role.value).model_dump(mode='json') if occurrence.role.value in alert.field_provenance else None,
            reliability=rel['reliability'] if rel else None,
            reliability_status='pair-specific frozen reliability' if rel else 'not selected for pair scoring; no hypothetical counterpart reliability assigned',
            frequency=idx.df[eid],population=idx.N,hot_high_frequency=scorer.evidence_evaluator.hot(eid),
            observation_identity=obs,evidence_pointer=dict(alert_id=alert.alert_id,pointer=occurrence.raw_pointer,side='shared'),
            shared_with_other=eid in other.entity_ids,legacy_selected_feature=evidence.get(eid),
            v4_reliability_detail=rel))
    return rows


def shared_roles(a,b,scorer,scored,features):
    idx=scorer.index
    rels={r['entity_id']:r for r in scored.diagnostics['evidence_v2']['entity_reliability']}
    rows=[]
    for eid in sorted(set(a.entity_ids)&set(b.entity_ids)):
        ar,br=sorted(idx.roles[a.alert_id][eid]),sorted(idx.roles[b.alert_id][eid])
        selected=[f for f in features if eid in f.get('entity_ids',[])]
        rel=rels.get(eid)
        rows.append(dict(entity_id=eid,type=idx.entities[eid].type.value,value=idx.entities[eid].value,
            a_roles=ar,b_roles=br,role_transitions=[x+' -> '+y for x in ar for y in br],
            role_compatible=True,role_factor=rel['role_factor'] if rel else None,
            role_conflict=False,role_note='Frozen scoring uses role factors; there is no separate role-incompatibility reject for these shared scoped identities.',
            participates_in_legacy_scoring=any(f['entity_id']==eid for f in scored.diagnostics['entity_features']),
            selected_in_v4_dimensions=[f['feature_name'] for f in selected],
            v4_contribution=math.fsum(f['net_contribution'] for f in selected),
            reliability=rel,hot=scorer.evidence_evaluator.hot(eid),
            ignored=not bool(selected),reason='selected maximum per type after reliability/role adjustment' if selected else 'not selected per-type maximum or consumed/suppressed'))
    return dict(shared_entities=rows,role_compatible_entities=[r['entity_id'] for r in rows],
        role_conflicting_entities=[],high_frequency_entities=[r['entity_id'] for r in rows if r['hot']],
        low_reliability_entities=[r['entity_id'] for r in rows if r['reliability'] and r['reliability']['reliability']<scorer.algorithm.score.evidence_v3.primary_minimum_reliability],
        ignored_entities=[r['entity_id'] for r in rows if r['ignored']])


def network_diagnostic(a,b,scorer,scored):
    audit=scored.diagnostics['evidence_v2']
    src,dst=sorted((a,b),key=lambda x:(scorer.index.times[x.alert_id],x.alert_id))
    dim=next(d for d in audit['dimensions'] if d['dimension']=='topology.network_continuity')
    return dict(continuity_detected=audit['network_continuity_valid'],continuity_type='topology.network_continuity',
        A_src=dict(ip=a.src_ip,port=a.src_port),A_dst=dict(ip=a.dst_ip,port=a.dst_port),
        B_src=dict(ip=b.src_ip,port=b.src_port),B_dst=dict(ip=b.dst_ip,port=b.dst_port),
        matching_entities=dim['entity_ids'],chronological_order=[src.alert_id,dst.alert_id],
        a_dst_equals_b_src=bool(a.dst_ip and a.dst_ip==b.src_ip),a_src_equals_b_dst=bool(a.src_ip and a.src_ip==b.dst_ip),
        chronological_dst_equals_src=bool(src.dst_ip and src.dst_ip==dst.src_ip),
        same_src_ip=bool(a.src_ip and a.src_ip==b.src_ip),same_dst_ip=bool(a.dst_ip and a.dst_ip==b.dst_ip),
        same_directed_ip_pair=bool(a.src_ip and a.dst_ip and a.src_ip==b.src_ip and a.dst_ip==b.dst_ip),
        same_host=bool(a.host and a.host==b.host),
        same_flow_id=a.raw_alert.get('flow_id') is not None and a.raw_alert.get('flow_id')==b.raw_alert.get('flow_id'),
        role_transition='chronological DST_IP -> SRC_IP',eligible=dim['state'].startswith('AVAILABLE'),
        normalized_strength=dim['strength'],reason=audit['network_diagnostic'],
        category_context=dict(a=a.category.value,b=b.category.value),
        diagnostic_only_comparisons=True,
        attacker_victim_status='src/dst are observed endpoints; attacker/victim roles are unverified')


def expand_pair(selected,rank,index,scorer,raw_lookup,population='candidate'):
    aid,bid=selected['support_pair']
    production_support_pair=[aid,bid]
    if population=='all_scored_members':
        aid,bid=sorted((aid,bid))
    a,b=index.alerts[aid],index.alerts[bid]
    scored=scorer.score_pair(aid,bid)
    assert scored.score==selected['score'], 'selected_pair_rescore_mismatch'
    breakdown=score_features(scored,scorer)
    assert breakdown['status']=='PASS'
    alerts={aid:a,bid:b}
    refs=validate_refs(scored,alerts)
    audit=scored.diagnostics['evidence_v2']
    mapping=relationship(scored,scorer,a,b)
    decision=rejection(scored,scorer.algorithm.score.correlation_threshold)
    raw={}
    for side,alert in (('A',a),('B',b)):
        records=raw_lookup[alert.raw_fingerprint]
        assert records and all(r['parsed_suricata_eve']==alert.raw_alert for r in records)
        raw[side]=dict(alert_id=alert.alert_id,raw_fingerprint=alert.raw_fingerprint,
            canonical_raw_evidence_pointer=dict(alert_id=alert.alert_id,pointer='',side='shared'),
            raw_evidence_pointer_count=1,outer_record_count=len(records),records=records,
            raw_root='CanonicalAlert.raw_alert is parsed EVE; original Splunk wrapper retained separately here.')
    observations=[dict(alert_id=x.alert_id,**asdict(scorer.duplicate.observation.identities[x.alert_id])) for x in (a,b)]
    observation_ids=sorted({o['observation_id'] for o in observations})
    signature=dict(A_signature=a.signature,A_signature_id=a.raw_alert.get('alert',{}).get('signature_id'),A_rule_id=a.rule_id,A_category=a.category.value,
        B_signature=b.signature,B_signature_id=b.raw_alert.get('alert',{}).get('signature_id'),B_rule_id=b.rule_id,B_category=b.category.value,
        same_signature=bool(a.signature and a.signature==b.signature),same_signature_id=bool(a.rule_id and a.rule_id==b.rule_id),
        same_category=a.category==b.category,legacy_behavior_score=scored.values['behavior'],
        semantic_feature='metadata.detector_identity',semantic_score=audit['family_strengths']['behavior'],
        severity_diagnostic_only=True,signature_id_is_rule_id=True,
        field_usage='rule/signature/category metadata is merged once; raw flow/IP comparisons are not new features')
    network=network_diagnostic(a,b,scorer,scored)
    network['score_contribution']=next(f['net_contribution'] for f in breakdown['features'] if f['feature_name']=='topology.network_continuity')
    canonical=dict(A=a.model_dump(mode='json'),B=b.model_dump(mode='json'))
    candidate=selected['candidate']
    member_windows=[dict(channel=e['channel'],effective_window_seconds=e['effective_window_seconds'],
        member_gap_seconds=scored.diagnostics['gap_seconds'],
        member_inside_window=scored.diagnostics['gap_seconds']<=e['effective_window_seconds'],
        nomination_member_ids=e['alert_ids'],nomination_gap_seconds=e['gap_seconds'])
        for e in candidate['evidence']]
    representative_id=id_for('CorrelationEdge',dict(source_alert_id=candidate['support_key'][0],target_alert_id=candidate['support_key'][1]))
    pair_id='cmp_'+content_digest(sorted((aid,bid))) if population=='all_scored_members' else representative_id
    return dict(rank=rank,pair_id=pair_id,representative_candidate_id=representative_id,
        pair_id_scope='diagnostic original-member comparison identity' if population=='all_scored_members' else 'prospective representative correlation identity; no formal edge was created',
        population=population,alert_a_id=aid,alert_b_id=bid,
        representative_alert_a_id=candidate['support_key'][0],representative_alert_b_id=candidate['support_key'][1],
        ranking_alert_a_id=selected['alert_a_id'],ranking_alert_b_id=selected['alert_b_id'],
        support_pair=dict(alert_a_id=aid,alert_b_id=bid),
        production_scored_support_pair=production_support_pair,
        alert_a_b_interpretation='Alert A/B IDs, CanonicalAlert A/B and raw A/B refer to the actual selected original members. Representative and ranking IDs are separately named; representative_candidate_id identifies their admitted candidate.',
        representative_alerts=dict(A=index.alerts[candidate['support_key'][0]].model_dump(mode='json'),B=index.alerts[candidate['support_key'][1]].model_dump(mode='json')),
        final_score=scored.score,formal_threshold=scorer.algorithm.score.correlation_threshold,
        threshold_gap=scored.score-scorer.algorithm.score.correlation_threshold,
        candidate_generated=True,
        production_candidate_decision=selected.get('production_candidate_summary'),
        production_member_rule_id=('score.correlation_threshold' if decision['formal_edge_admitted'] else
            'below_correlation_threshold' if scored.valid else 'invalid_member_pair'),
        relationship_type=mapping['selected_relationship'],relationship_mapping_result=mapping,
        **decision,canonical_alerts=canonical,raw_alerts=raw,
        entity_extraction=dict(A=entities_for(a,b,scorer,scored),B=entities_for(b,a,scorer,scored)),
        shared_entity_role_matching=shared_roles(a,b,scorer,scored,breakdown['features']),
        scoring=breakdown,production_score_breakdown=scorer.breakdown(scored).model_dump(mode='json'),
        production_reasons=[r.model_dump(mode='json') for r in scored.reasons],
        evidence_independence=dict(observations=observations,independent_observation_count=len(observation_ids),
            count_semantics='distinct frozen observation identities, not proof of statistically independent sources',
            source_independence=scored.source_independence,observation_ids=observation_ids,
            evidence_types=audit['evidence_families'],fact_count=len(audit['evidence']),facts=audit['evidence'],
            duplicate_observations_removed=2-len(observation_ids),duplicate_risk=audit['duplicate_observation_risk'],
            suppressed_dimensions=audit['suppressed_dimensions'],
            metadata_only=not any(f['family'] not in ('RULE_METADATA','TEMPORAL') for f in audit['evidence']),
            primary_evidence=audit['primary_evidence'],supporting_evidence=audit['supporting_evidence'],
            independence_result=audit['gate_reason'],raw_evidence_pointers=refs),
        temporal=dict(alert_a_timestamp=a.timestamp,alert_b_timestamp=b.timestamp,
            absolute_time_delta_seconds=scored.diagnostics['gap_seconds'],half_life_seconds=scored.diagnostics['half_life_seconds'],
            candidate_windows=candidate['evidence'],member_window_checks=member_windows,
            inside_candidate_window=any(w['member_inside_window'] for w in member_windows) if member_windows else None,
            candidate_group_nomination_admitted=True,
            member_window_caveat='Candidate eligibility uses frozen full-group nomination evidence; selected member delta need not equal nomination member delta.',
            temporal_feature_value=scored.values['time'],
            temporal_score_contribution=next(f['net_contribution'] for f in breakdown['features'] if f['feature_name']=='time.distance'),
            reasonable_behavior_windows=[r.model_dump(mode='json') for r in scorer.algorithm.time.transition_half_lives
                if (r.from_category,r.to_category) in [(x.category.value,y.category.value) for x,y in scorer.ordered_pairs(a,b)]]),
        network_continuity=network,signature_semantics=signature,guards=guards(scored,scorer),
        downstream_guards=dict(evaluated=False,status='NOT_REACHED_NO_CORRELATION_EDGE' if not decision['formal_edge_admitted'] else 'NOT_RUN_DIAGNOSTIC_ONLY',
            clustering_config=scorer.algorithm.clustering.model_dump(mode='json'),
            chain_config=scorer.algorithm.chain.model_dump(mode='json')),
        candidate_admission=candidate,production_diagnostic=scored.diagnostics,
        verification=dict(score_matches_selection=True,score_reconstructs=True,raw_pointer_traceability=True,
            original_raw_matches_canonical=True,alert_a_b_binding=True))


def distributions():
    sqlite=sqlite3.connect(OUT/'compact_scores.sqlite')
    sqlite.execute('PRAGMA cache_size=-8192')
    sqlite.execute('PRAGMA temp_store=FILE')
    result={}
    for population in ('candidates','members'):
        row=sqlite.execute('''SELECT count(*),max(score),
            count(*) FILTER(WHERE score>=.65),count(*) FILTER(WHERE score>=.60 AND score<.65),
            count(*) FILTER(WHERE score>=.55 AND score<.60),count(*) FILTER(WHERE score>=.50 AND score<.55),
            count(*) FILTER(WHERE score<.50) FROM '''+population).fetchone()
        stats=dict(zip(('total_scored_pairs','max_score','count_score_ge_0_65','count_score_0_60_0_65',
            'count_score_0_55_0_60','count_score_0_50_0_55','count_score_lt_0_50'),row))
        levels=dict(p99_99=.9999,p99_9=.999,p99=.99,p95=.95,median=.5)
        positions={k:(row[0]-1)*q for k,q in levels.items()}
        needed={i for pos in positions.values() for i in (int(pos),min(int(pos)+1,row[0]-1))}
        values={}
        # SQLite performs external ORDER BY; Python sees scalar batches only.
        cursor=sqlite.execute('SELECT score FROM '+population+' ORDER BY score')
        offset=0
        for batch in iter(lambda:cursor.fetchmany(10000),[]):
            for i,(score,) in enumerate(batch,offset):
                if i in needed:
                    values[i]=score
            offset+=len(batch)
        for k,pos in positions.items():
            lo=int(pos);hi=min(lo+1,row[0]-1)
            stats[k]=values[lo]+(values[hi]-values[lo])*(pos-lo)
        result[population]=stats
    sqlite.close()
    result['candidates']['population']='All admitted/scored representative candidates: highest valid member, otherwise highest rejected member, exactly matching original Step3A audit.'
    result['members']['population']='All individual member comparisons of those same candidates, including guard/evidence failures; no member was filtered before ranking.'
    baseline=read_json(RUN/'score_distribution.json')
    assert result['candidates']['total_scored_pairs']==baseline['scored_pairs']
    for new,old in (('max_score','max'),('p99','P99'),('p95','P95'),('median','median')):
        assert abs(result['candidates'][new]-baseline['quantiles'][old])<=TOLERANCE, 'distribution_replay_mismatch'
    return result


def verify_disk_selection(selections,members):
    """Independent disk ORDER BY checks both heaps, including boundary ties."""
    db=sqlite3.connect(OUT/'compact_scores.sqlite')
    db.execute('PRAGMA cache_size=-8192')
    db.execute('PRAGMA temp_store=FILE')
    ids=dict(db.execute('SELECT i,id FROM alerts'))
    for selected,query in ((selections,'SELECT ra,rb,score FROM candidates ORDER BY score DESC,ra,rb LIMIT 100'),
            (members,'SELECT min(a,b),max(a,b),score FROM members ORDER BY score DESC,min(a,b),max(a,b) LIMIT 100')):
        rows=db.execute(query).fetchall()
        assert len(selected)==len(rows)==100
        assert [(s['alert_a_id'],s['alert_b_id'],s['score']) for s in selected]==[
            (ids[a],ids[b],score) for a,b,score in rows], 'global_top100_heap_sql_mismatch'
    db.close()
    return True


def attach_candidate_decisions(selections,members,threshold):
    """Keep original aggregate decisions distinct from rejected raw members."""
    db=sqlite3.connect(OUT/'compact_scores.sqlite')
    lookup={aid:i for i,aid in db.execute('SELECT i,id FROM alerts')}
    db.execute('CREATE TEMP TABLE requested(ra INT,rb INT,PRIMARY KEY(ra,rb))')
    db.executemany('INSERT OR IGNORE INTO requested VALUES (?,?)',[
        tuple(lookup[a] for a in s['candidate']['support_key']) for s in selections+members])
    decisions={}
    for ra,rb,a,b,score,valid in db.execute('''SELECT x.id,y.id,u.id,v.id,c.score,c.valid
        FROM candidates c JOIN requested q ON c.ra=q.ra AND c.rb=q.rb
        JOIN alerts x ON c.ra=x.i JOIN alerts y ON c.rb=y.i
        JOIN alerts u ON c.a=u.i JOIN alerts v ON c.b=v.i'''):
        accepted=bool(valid and score>=threshold)
        decisions[(ra,rb)]=dict(support_key=[ra,rb],selected_support_pair=[a,b],
            selected_member_is_valid=bool(valid),diagnostic_score=score,formal_candidate_score=score if valid else None,
            formal_edge_admitted=accepted,decision='accept' if accepted else 'reject',
            rule_id='score.correlation_threshold' if accepted else 'below_correlation_threshold' if valid else 'no_valid_member_pair')
    db.close()
    for selected in selections+members:
        selected['production_candidate_summary']=decisions[tuple(selected['candidate']['support_key'])]


def feature_stats(pairs):
    features=defaultdict(list)
    for pair in pairs:
        for f in pair['scoring']['features']:
            features[f['feature_name']].append(f)
    stats=[]
    for name,rows in sorted(features.items()):
        contributions=[r['net_contribution'] for r in rows]
        stats.append(dict(feature=name,eligible_pairs=sum(r['eligible'] for r in rows),
            non_zero_pairs=sum(v!=0 for v in contributions),mean_contribution=math.fsum(contributions)/len(rows),
            max_contribution=max(contributions),min_contribution=min(contributions),
            states=dict(Counter(r.get('state','PENALTY') for r in rows))))
    return dict(pair_count=len(pairs),features=stats)


def findings(pairs):
    n=len(pairs)
    counts=Counter()
    same_src_signatures=defaultdict(set);same_dst_signatures=defaultdict(set)
    categories=Counter();network_reasons=Counter();gate_reasons=Counter()
    for p in pairs:
        net=p['network_continuity']; sig=p['signature_semantics']; ev=p['production_diagnostic']['evidence_v2']
        network_reasons[ev['network_diagnostic']]+=1
        gate_reasons[ev['gate_reason']]+=1
        categories[(sig['A_category'],sig['B_category'])]+=1
        counts['any_unknown_category']+='unknown' in (sig['A_category'],sig['B_category'])
        counts['source_independence_unknown']+=p['evidence_independence']['source_independence']=='unknown'
        counts['metadata_strength_zero']+=ev['family_strengths']['behavior']==0
        same=net['same_directed_ip_pair']
        counts['same_src_ip_same_dst_ip']+=same
        counts['same_src_ip_same_dst_ip_close_time']+=same and p['temporal']['absolute_time_delta_seconds']<=60
        counts['same_flow_id']+=net['same_flow_id']
        counts['same_signature_repeated']+=sig['same_signature']
        counts['different_signatures_same_communication_ip_pair']+=same and not sig['same_signature']
        counts['same_src_ip_multiple_signatures_pair']+=net['same_src_ip'] and not sig['same_signature']
        counts['same_dst_ip_multiple_signatures_pair']+=net['same_dst_ip'] and not sig['same_signature']
        counts['A_dst_equals_B_src']+=net['a_dst_equals_b_src']
        counts['chronological_dst_equals_src']+=net['chronological_dst_equals_src']
        counts['network_continuity_positive']+=net['normalized_strength']>0
        counts['below_threshold']+=not p['threshold_passed']
        counts['pure_threshold_rejection']+=p['primary_rejection_reason']=='REJECTED_BELOW_THRESHOLD'
        counts['hard_guard_rejection']+=p['primary_rejection_reason']=='REJECTED_BY_GUARD'
        counts['evidence_gate_failed']+=not ev['evidence_gate_passed']
        counts['duplicate_observation_risk']+=ev['duplicate_observation_risk']
        counts['chain_mapping_absent']+=p['relationship_type']=='NONE'
        counts['mapping_caused_correlation_rejection']+=0
        roles=p['shared_entity_role_matching']
        counts['any_hot_shared_entity']+=bool(roles['high_frequency_entities'])
        counts['any_low_reliability_shared_entity']+=bool(roles['low_reliability_entities'])
        counts['role_incompatibility_rejection']+=bool(roles['role_conflicting_entities'])
        counts['destination_only_role_discount']+=any(r['reliability'] and r['reliability']['role_factor']==.25 for r in roles['shared_entities'] if r['type']=='IP')
        counts['penalty_conflict_nonzero']+=p['scoring']['legacy_seven_component_audit']['raw_values']['conflict']>0
        counts['penalty_duplicate_nonzero']+=p['scoring']['legacy_seven_component_audit']['raw_values']['duplicate']>0
        for alert in p['canonical_alerts'].values():
            if alert['src_ip']:
                same_src_signatures[alert['src_ip']].add(alert['signature'])
            if alert['dst_ip']:
                same_dst_signatures[alert['dst_ip']].add(alert['signature'])
    return dict(top_pair_count=n,counts=dict(counts),close_time_seconds=60,
        category_pairs=[dict(a=k[0],b=k[1],count=v) for k,v in sorted(categories.items())],
        network_diagnostic_reasons=dict(network_reasons),evidence_gate_reasons=dict(gate_reasons),
        overlapping_diagnostics=True,counts_are_pair_counts_unless_explicitly_named_unique=True,
        unique_source_ips_with_multiple_signatures=sum(len(v)>1 for v in same_src_signatures.values()),
        unique_destination_ips_with_multiple_signatures=sum(len(v)>1 for v in same_dst_signatures.values()),
        attacker_victim_assertion='Not established: same src/dst is an endpoint proxy only; no GT was read.',
        scope='Top100 observed candidate support pairs only; this is not recall, attack confirmation, or a census of all theoretical pairs.')


def table(pairs):
    lines=['| Rank | Alert A | Alert B | Δt(s) | Positive | Penalty | Final | Gap to 0.65 | Shared Evidence | Relationship | Reject Reason |',
           '|---|---|---|---:|---:|---:|---:|---:|---|---|---|']
    for p in pairs:
        evidence=', '.join(p['production_diagnostic']['evidence_v2']['matched_evidence'])
        lines.append('| '+str(p['rank'])+' | '+p['alert_a_id']+' | '+p['alert_b_id']+' | '+f"{p['temporal']['absolute_time_delta_seconds']:.6f}"+' | '+
            ' | '.join(f"{v:.9f}" for v in (p['scoring']['positive_score_total'],p['scoring']['penalty_total'],p['final_score'],p['threshold_gap']))+
            ' | '+evidence+' | '+p['relationship_type']+' | '+p['primary_rejection_reason']+' |')
    return '\n'.join(lines)


def report(pairs,dist,stats,finding):
    c=finding['counts']; n=len(pairs)
    positive=sorted((f for f in stats['features'] if not f['feature'].startswith('penalty.') and f['non_zero_pairs']),
        key=lambda f:(-f['non_zero_pairs'],-f['mean_contribution'],f['feature']))
    missing=sorted((f for f in stats['features'] if f['states'].get('UNAVAILABLE',0)+f['states'].get('NOT_APPLICABLE',0)),
        key=lambda f:(-f['states'].get('UNAVAILABLE',0)-f['states'].get('NOT_APPLICABLE',0),f['feature']))
    positive_text='; '.join(f"{f['feature']}: {f['non_zero_pairs']}/{n}, mean +{f['mean_contribution']:.6f}" for f in positive[:6])
    missing_text='; '.join(f"{f['feature']}: unavailable={f['states'].get('UNAVAILABLE',0)}, not-applicable={f['states'].get('NOT_APPLICABLE',0)}" for f in missing)
    lines=['# CPTC Top 100 Candidate Pair Diagnostic',table(pairs),
        '## Scope and reproducibility',
        'Exact accepted t5 snapshot; no new input partition. The PRIMARY Top100 ranks every actually scored original-member comparison of the admitted candidates, including invalid/guard-rejected members, by final_score DESC, lexical member A ID ASC, member B ID ASC. Table Alert A/B and raw/canonical evidence refer to the actual original members; ranking IDs explicitly store the lexical pair. No valid-member preference filters this primary ranking.',
        'A separate representative-candidate Top100 uses the original Step3A aggregate convention: highest valid member, otherwise highest rejected member. This distinguishes the 1,551,265 representative candidates and 1,708,390 completed member comparisons without hiding high-scoring rejected members. Each expansion is bounded to its 100 selected comparisons. No full original pair identity stream survived the old run; replay equivalence is based on identical immutable input/code/config, deterministic generation, exact original count/histogram/decision comparisons, Top20 exact score checks, and original candidate percentile checks. The replay digest is a new receipt, not a historical digest match.',
        'Historical diagnostic-tool observation: scripts/cptc_2018_step3a.py Observer retains lexically larger candidate IDs at the heap cutoff when scores tie, then displays retained IDs ascending. This differs from the requested global ascending-ID tie-break. The original tool was not modified; this diagnostic uses the requested tie-break and independently verifies both global lists with disk SQL. This is an audit-ranking issue, not a scoring/guard change.',
        '## Score Distribution', '```json\n'+jdump(dist)+'\n```',
        '## Top 100 Feature Frequency','| Feature | Eligible | Non-zero | Mean | Min | Max |','|---|---:|---:|---:|---:|---:|']
    for f in stats['features']:
        lines.append(f"| {f['feature']} | {f['eligible_pairs']} | {f['non_zero_pairs']} | {f['mean_contribution']:.9f} | {f['min_contribution']:.9f} | {f['max_contribution']:.9f} |")
    conclusions=['## Why Top CPTC Candidate Pairs Fail Admission',
        f"Q1. Most frequent positive evidence: {positive_text}. Several metadata fields collapse into one detector fact.",
        f"Q2. Missing/unavailable frozen dimensions: {missing_text}. NOT_APPLICABLE and UNAVAILABLE are reported separately and are not measured mismatches.",
        f"Q3. Conflict penalty is nonzero for {c.get('penalty_conflict_nonzero',0)}/{n}; duplicate penalty for {c.get('penalty_duplicate_nonzero',0)}/{n}. Zero penalties cannot explain a low score.",
        f"Q4. {c.get('same_src_ip_same_dst_ip',0)}/{n} share directed src/dst IPs; {c.get('destination_only_role_discount',0)}/{n} have a destination-only IP role factor of 0.25, {c.get('any_low_reliability_shared_entity',0)}/{n} contain shared entities below the 0.6 primary reliability cutoff, and {c.get('any_hot_shared_entity',0)}/{n} contain hot shared entities. These overlap and are not independent rejection counts.",
        f"Q5. The same-src/same-dst proxy occurs in {c.get('same_src_ip_same_dst_ip',0)}/{n}; attacker and victim identities and common attack membership are unverified. {c.get('below_threshold',0)}/{n} are below threshold.",
        f"Q6. A.dst == B.src occurs in {c.get('A_dst_equals_B_src',0)}/{n}; chronological dst→src occurs in {c.get('chronological_dst_equals_src',0)}/{n}. Positive frozen continuity appears in {c.get('network_continuity_positive',0)}/{n}; every actual continuity contribution is recorded per pair.",
        f"Q7. Pure threshold rejection: {c.get('pure_threshold_rejection',0)}/{n}; hard guard: {c.get('hard_guard_rejection',0)}/{n}; evidence-gate failure: {c.get('evidence_gate_failed',0)}/{n}; duplicate observation risk: {c.get('duplicate_observation_risk',0)}/{n}. Chain mapping absent: {c.get('chain_mapping_absent',0)}/{n}, but mapping caused 0 undirected-correlation rejections. No separate role-incompatibility rejection is implemented for these shared identities.",
        'v4 score reconstruction uses quality + mass minus penalties, with each frozen dimension allocated through its family. The legacy seven signed contributions are also preserved; their sum is not the v4 final score. Absence of directional mapping is a downstream ChainEdge constraint and is not a CorrelationEdge admission gate.',
        '## Suricata Single-Source Diagnostic','```json\n'+jdump(finding)+'\n```',
        f"Observed network/semantic overlap is measurable: {c.get('same_src_ip_same_dst_ip',0)}/{n} same directed IP pair, {c.get('different_signatures_same_communication_ip_pair',0)}/{n} different signatures on that pair, {c.get('same_flow_id',0)}/{n} same flow ID. These observations show shared context among this Top100, but do not establish a shared attack process or how many qualifying pairs exist outside the admitted universe.",
        ]
    lines += ['## Individual Pair Expansions']
    for p in pairs:
        lines += [f"### Rank {p['rank']}: {p['pair_id']}",
            f"Final={p['final_score']:.12f}; gap={p['threshold_gap']:.12f}; primary={p['primary_rejection_reason']}; secondary={', '.join(p['secondary_rejection_reasons']) or 'NONE'}.",
            'CanonicalAlert A / B (all actual fields, including nulls)', '```json\n'+jdump(p['canonical_alerts'])+'\n```',
            'Raw Alert A / B: original outer record and complete parsed EVE', '```json\n'+jdump(p['raw_alerts'])+'\n```',
            'Entity extraction, roles and matching','```json\n'+jdump(dict(entities=p['entity_extraction'],matching=p['shared_entity_role_matching']))+'\n```',
            'All frozen scoring dimensions, positive contributions and penalties','```json\n'+jdump(p['scoring'])+'\n```',
            'Observations / independence / pointer grounding','```json\n'+jdump(p['evidence_independence'])+'\n```',
            'Temporal / network / signature / mapping / guards','```json\n'+jdump({k:p[k] for k in ('temporal','network_continuity','signature_semantics','relationship_mapping_result','guards')})+'\n```']
    lines += conclusions + ['DIAGNOSIS COMPLETE', 'No frozen algorithm, threshold, weight, mapping, guard, or production configuration was modified during this task.']
    (OUT/'CPTC_TOP100_DIAGNOSTIC_REPORT.md').write_text('\n\n'.join(lines)+'\n',encoding='utf8')
    summary=['# CPTC Top100 Summary',table(pairs),'## Frozen recipe','```json\n'+jdump(read_json(OUT/'FROZEN_RECIPE.json'))+'\n```',
        '## Score distribution','```json\n'+jdump(dist)+'\n```',
        '## Findings','```json\n'+jdump(finding)+'\n```',
        'Primary population: every completed original-member comparison of the original admitted candidate universe, including invalid members. The separate CANDIDATE_AGGREGATES file preserves the original representative convention (highest valid member, otherwise highest rejected). Both distributions are reported. Detailed report contains complete raw/canonical/evidence per primary Top100 pair.',
        'DIAGNOSIS COMPLETE']
    (OUT/'CPTC_TOP100_SUMMARY.md').write_text('\n\n'.join(summary)+'\n',encoding='utf8')


def expand():
    started=time.perf_counter()
    assert read_json(OUT/'replay_complete.json')['status']=='PASS'
    before=read_json(OUT/'protected_before.json')
    assert protected_hashes()==before
    config,settings,recipe=frozen()
    selections=read_json(OUT/'top100_selection.json')
    members=read_json(OUT/'top100_all_members_selection.json')
    verify_disk_selection(selections,members)
    attach_candidate_decisions(selections,members,config.algorithm.score.correlation_threshold)
    dist=distributions()
    with truth_guard(ROOT),saved_index(config,settings,OUT/'expansion_spill') as (index,scorer):
        fingerprints={index.alerts[aid].raw_fingerprint for sel in selections+members for aid in sel['support_pair']}
        lookup={fp:[] for fp in fingerprints}
        for record in read_cptc_file(INPUT):
            assert not record.error
            fp=raw_fingerprint(record.eve)
            if fp in lookup:
                lookup[fp].append(dict(input_file=INPUT.relative_to(ROOT).as_posix(),ordinal=record.ordinal,
                    outer_record=record.wrapper,parsed_suricata_eve=record.eve,
                    outer_evidence_pointer=f'/{record.ordinal-1}/_raw',
                    locator_semantics='zero-based pointer into outer export array; ordinal is a locator only, never stable identity'))
        assert all(lookup.values()),'raw_record_not_found'
        pairs=[expand_pair(s,i,index,scorer,lookup) for i,s in enumerate(selections,1)]
        all_members=[expand_pair(s,i,index,scorer,lookup,'all_scored_members') for i,s in enumerate(members,1)]
    candidate_pairs=pairs
    pairs=all_members
    for name,rows in (('CPTC_TOP100_PAIRS.jsonl',pairs),('CPTC_TOP100_ALL_MEMBERS_PAIRS.jsonl',pairs),
                     ('CPTC_TOP100_CANDIDATE_AGGREGATES_PAIRS.jsonl',candidate_pairs)):
        with (OUT/name).open('w',encoding='utf8',newline='\n') as f:
            for row in rows:
                f.write(json.dumps(row,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n')
    stats=feature_stats(pairs); finding=findings(pairs)
    atomic_json(OUT/'CPTC_TOP100_SCORE_DISTRIBUTION.json',dict(**dist['members'],representative_candidate_scores=dist['candidates']))
    atomic_json(OUT/'CPTC_TOP100_FEATURE_STATS.json',stats)
    atomic_json(OUT/'CPTC_TOP100_SINGLE_SOURCE.json',finding)
    atomic_json(OUT/'CPTC_TOP100_ALL_MEMBERS_FINDINGS.json',findings(all_members))
    atomic_json(OUT/'CPTC_TOP100_CANDIDATE_AGGREGATE_FINDINGS.json',findings(candidate_pairs))
    report(pairs,dist,stats,finding)
    assert protected_hashes()==before
    replay=read_json(OUT/'replay_complete.json')
    manifest=dict(task_result='CPTC_TOP100_DIAGNOSTIC_COMPLETE',dataset='CPTC-2018 t5',
        raw_alert_count=read_json(RUN/'experiment_summary.json')['dataset']['raw'],
        canonical_alert_count=recipe['input_count'],
        representative_count=read_json(RUN/'experiment_summary.json')['representatives'],
        input_file=INPUT.relative_to(ROOT).as_posix(),input_sha256=file_digest(INPUT),
        original_run_manifest=str((RUN/'manifest.json').relative_to(ROOT)).replace('\\','/'),
        original_run_manifest_sha256=file_digest(RUN/'manifest.json'),
        algorithm_version=recipe['algorithm_version'],config_hash=recipe['config_hash'],mapping_digest=recipe['mapping_digest'],
        threshold=config.algorithm.score.correlation_threshold,total_candidate_pairs=replay['candidate_count'],
        total_scored_pairs=replay['member_count'],total_scored_representative_candidates=replay['candidate_count'],
        total_scored_member_pairs=replay['member_count'],top_k=100,
        max_score=dist['members']['max_score'],algorithm_modified=False,config_modified=False,raw_data_modified=False,
        ground_truth_read=False,original_t5_artifacts_unchanged=True,protected_files_verified=len(before),
        repository_state=dict(git_commit=None,reason='Workspace has no .git metadata; source file SHA256 state preserved in protected_before.json',
            code_state_sha256=content_digest(before)),
        diagnostic_code={p.name:file_digest(p) for p in (ROOT/'scripts/cptc_top100_diagnostic.py',Path(__file__))},
        ranking='final_score DESC, lexical original-member alert_a_id ASC, alert_b_id ASC; invalid members included',
        representative_candidate_ranking='final_score DESC, representative alert_a_id ASC, alert_b_id ASC',
        all_member_ranking='score DESC, canonical lexical member alert_a_id ASC, alert_b_id ASC; invalid members included',
        population_semantics=dist['members']['population'],
        reproduction_limitation=read_json(OUT/'candidate_replay_verification.json')['identity_verification'],
        historical_diagnostic_issue=dict(path='scripts/cptc_2018_step3a.py',
            sha256=file_digest(ROOT/'scripts/cptc_2018_step3a.py'),
            issue='Observer heap retains lexical largest candidate IDs at equal-score cutoff, unlike requested ascending-ID retention.',
            original_tool_modified=False,production_algorithm_affected=False),
        verification=dict(replay_aggregates='PASS',historical_top20_scores='PASS',original_percentiles='PASS',
            independent_sql_top100='PASS',
            top100_rescore='PASS',score_reconstruction='PASS',raw_ownership_and_roundtrip='PASS'),
        expansion_elapsed_seconds=time.perf_counter()-started,
        files={p.name:file_digest(p) for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='CPTC_TOP100_MANIFEST.json'})
    atomic_json(OUT/'CPTC_TOP100_MANIFEST.json',manifest)
    log('diagnosis_complete',pairs=len(pairs),expansion_elapsed_seconds=time.perf_counter()-started)

"""Offline evidence profiling and cards. No production caller or domain writes.

Completeness is an experimental dependency-coverage label, not attack confidence.
Missing source fields stay UNKNOWN unless an explicit schema attestation exists.
"""
from collections import Counter, defaultdict
from copy import deepcopy
import math

import v5_design_diagnostic as diagnostic
from app.models.base import resolve_pointer

FIELDS = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'host',
          'account', 'session', 'process', 'parent_process', 'url', 'domain',
          'file', 'command', 'rule_id', 'signature', 'category', 'protocol', 'flow_id')
FAMILY_FIELDS = {
    'temporal': ('timestamp',), 'network': ('src_ip', 'dst_ip'),
    'host': ('host',), 'identity': ('account', 'session'),
    'process': ('process', 'parent_process'),
    'application': ('url', 'domain', 'file', 'command'),
    'detector_semantics': ('rule_id', 'signature'), 'attack_semantics': ('category',),
    'transport': ('protocol', 'src_port', 'dst_port', 'flow_id')}


def present(value):
    return value is not None and value != '' and value != 'unknown'


def field_values(alert):
    values = {f: getattr(alert, f) for f in FIELDS if f not in ('protocol', 'flow_id')}
    values['category'] = alert.category.value
    raw = alert.raw_alert
    body = raw.get('data', raw)
    values.update(protocol=body.get('proto', body.get('protocol')), flow_id=body.get('flow_id'))
    return values


def evidence_profile(values):
    """Derived from prerequisites of entity, flow, metadata and time evaluators.

    HIGH needs a complete endpoint+transport bundle, or host+identity+process.
    MEDIUM has a usable scoped-context candidate field but lacks that bundle.
    SPARSE has no canonical candidate context beyond detector/time metadata.
    Resources alone need an explicit target to count as usable context.
    """
    p = {f: present(values.get(f)) for f in FIELDS}
    families = {f: any(p[k] for k in keys) for f, keys in FAMILY_FIELDS.items()}
    network_bundle = all(p[k] for k in ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'))
    host_bundle = p['host'] and (p['account'] or p['session']) and p['process']
    context = any(p[k] for k in ('src_ip', 'dst_ip', 'host', 'account', 'session',
                                'process', 'parent_process', 'domain'))
    context |= p['url'] and (p['host'] or p['dst_ip'] or p['domain'])
    level = 'HIGH' if (network_bundle or host_bundle) else 'MEDIUM' if context else 'SPARSE'
    return dict(evidence_profile=families, evidence_completeness=level,
                scoring_prerequisites=dict(complete_network_bundle=network_bundle,
                    host_identity_process_bundle=host_bundle, usable_candidate_context=bool(context)))


def source_family(alert, settings):
    raw = alert.raw_alert
    if 'AnalysisComponent' in raw:
        detector = raw['AnalysisComponent'].get('AnalysisComponentType', 'unknown')
    else:
        detector = raw.get('decoder', {}).get('name', raw.get('event_type', 'unknown'))
    return '|'.join((alert.source_type.value, alert.alert_type or 'unknown',
                     detector, settings.format_profile))


def capability(count, total, schema_excludes=False):
    if count:
        return 'AVAILABLE' if count == total else 'OPTIONAL'
    return 'UNAVAILABLE_BY_SOURCE' if schema_excludes else 'UNKNOWN'


def profile_alerts(alerts, settings, dataset):
    groups = defaultdict(list)
    distribution = Counter()
    rows = []
    for a in alerts:
        values = field_values(a)
        prof = evidence_profile(values)
        distribution[prof['evidence_completeness']] += 1
        family = source_family(a, settings[a.source_namespace])
        groups[family].append((a, values, prof))
        # All rows retain IDs and provenance, without copying raw alert payloads.
        rows.append(dict(alert_id=a.alert_id, raw_fingerprint=a.raw_fingerprint,
            source_family=family, **prof))
    observed = []
    for family, members in sorted(groups.items()):
        n = len(members)
        fields = Counter(k for _, v, _ in members for k in FIELDS if present(v[k]))
        fams = Counter(k for _, _, p in members for k, v in p['evidence_profile'].items() if v)
        observed.append(dict(source_family=family, sample_count=n, datasets=[dataset],
            field_statistics={k:dict(present=fields[k], total=n, rate=fields[k]/n) for k in FIELDS},
            evidence_capabilities={k:dict(status=capability(fams[k], n), present=fams[k],
                total=n, rate=fams[k]/n, conditional_presence_rate_given_detector_profile=fams[k]/n)
                for k in FAMILY_FIELDS},
            confidence='OBSERVED_PROFILE_ONLY', evidence=[dict(alert_id=a.alert_id,
                raw_fingerprint=a.raw_fingerprint) for a, _, _ in members[:3]],
            limitations=['0/N is UNKNOWN; no attested schema exclusion in available deployment metadata.',
                'AVAILABLE means observed in all sampled records, not a vendor-wide guarantee.',
                'Process describes fields; pid/name alone is not an instance or lineage.']))
    return distribution, observed, rows


def absence_audit(alert):
    """Separate extractor absence from absent raw facts without new extraction.

    Adapter provenance proves extraction success. Raw keys suggest unextracted
    evidence, but arbitrary snippets are never parsed into new canonical fields.
    """
    raw = alert.raw_alert
    keys = set()
    def walk(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if present(v):
                    keys.add(k.lower())
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
    walk(raw)
    aliases = {'host': {'host', 'hostname'}, 'account': {'user', 'srcuser', 'dstuser', 'account'},
        'process': {'process', 'pid', 'exe', 'comm'}, 'session': {'session'},
        'url': {'url'}, 'domain': {'hostname', 'sni', 'rrname', 'domain'},
        'src_ip': {'src_ip', 'srcip'}, 'dst_ip': {'dest_ip', 'dstip', 'dst_ip'}}
    result = {}
    for f, names in aliases.items():
        if present(getattr(alert, f)):
            ref = alert.field_provenance[f]
            resolve_pointer(raw, ref.raw_pointer)
            result[f] = dict(status='EXTRACTED', raw_pointer=ref.raw_pointer, transform=ref.transform)
        else:
            raw_keys = sorted(names & keys)
            # No schema/parse-failure claim from string searching. Snippets may
            # contain unrecognized fields; absence is scoped to mapped structures.
            result[f] = dict(status='RAW_PRESENT_CANONICAL_MISSING_REQUIRES_REVIEW' if raw_keys
                             else 'missing_in_raw_mapped_structures', matching_keys=raw_keys,
                normalization_failed=False, normalization_failure_status='NOT_PROVEN',
                limitation='Unparsed snippets/aggregate path vectors may contain other information.')
    return result


def compare(view, policy):
    """Keep A-D formulas unchanged and add auditable weight accounting."""
    scores = diagnostic.compare(view, policy)
    summary = diagnostic.summarize(view, policy)
    unknown_families = {d['family'] for d in view['dimensions'] if d['state']=='UNKNOWN'}
    unobservable = {d['family'] for d in view['dimensions'] if d['state']=='UNOBSERVABLE'}
    observable = {d['family'] for d in view['dimensions'] if d['state'] in ('SUPPORTED', 'CONTRADICTED')}
    for key, row in scores.items():
        raw = summary['relation_score'] - view['penalty']
        if key == 'c':
            raw = summary['relation_score']*summary['confidence'] - policy['contradiction_factor']*summary['mismatch_mass']-view['penalty']
        row.update(available_weight=summary['observable_weight'], matched_weight=summary['supported_weight'],
            negative_weight=summary['mismatch_mass'], unavailable_weight=0.0,
            unknown_weight=math.fsum(view['weights'][f] for f in unknown_families-observable),
            missing_observation_weight=math.fsum(view['weights'][f] for f in unobservable-observable-unknown_families),
            raw_score=raw, normalized_score=row['score'], score_delta_vs_v4=row['score']-view['v4_score'],
            weight_accounting='Family weights partition observable / unknown / missing. Negative_weight is observable disagreement subset; no attested source exclusion.',
            delta_reasons=['A-D reuse existing state_projection; unproven topology becomes UNKNOWN, not refutation.',
                'A/B/D use Q without v4 fixed mass blend; C multiplies absolute support confidence and subtracts mismatch.',
                'Frozen penalties/primary/duplicate guards retained; no source absence adds confidence.'])
    return scores


def pair_states(view):
    states = {}
    for d in view['dimensions']:
        states[d['dimension']] = dict(
            state={'SUPPORTED':'AVAILABLE', 'CONTRADICTED':'PRESENT_BUT_NONMATCHING',
                'UNKNOWN':'UNKNOWN', 'UNOBSERVABLE':'MISSING_OBSERVATION',
                'NOT_APPLICABLE':'NOT_APPLICABLE'}[d['state']],
            diagnostic_state=d['state'], v4_state=d['v4_state'], basis=d['basis'])
    return states


def semantic_review(a, b, scorer, pair):
    """Conservative, score-blind evidence rubric; labels are provisional review.

    Same endpoints/signature/clock never suffice. Shared specific request plus
    relevant detector text and independent observation are required for step
    compatibility. No success, intent, causal progression or true attack claim.
    """
    da, db = field_values(a), field_values(b)
    gap = pair.diagnostics['gap_seconds']
    observation = pair.diagnostics['duplicate_features'].get('observation_identity', {})
    if observation.get('equivalent') or a.raw_fingerprint == b.raw_fingerprint:
        return ('REPEATED_OBSERVATION', 'HIGH',
                'Frozen observation matcher identifies the same underlying observation; unsuitable for two chain steps.')
    if pair.relations:
        return ('ATTACK_PROGRESSION', 'MEDIUM',
                'Frozen verifier returned field-backed propagation. Review relation pointers before claiming attack success.')
    same_endpoint = a.dst_ip and a.dst_ip == b.dst_ip and a.dst_port is not None and a.dst_port == b.dst_port
    same_source = a.src_ip and a.src_ip == b.src_ip and a.source_namespace == b.source_namespace
    specific_url = a.url and a.url == b.url and a.url not in ('/', '.', '') and (
        a.domain and a.domain == b.domain)
    text_a, text_b = (str(x.signature or '').lower() for x in (a,b))
    relevant = lambda s: any(w in s for w in ('exploit', 'traversal', 'injection', 'nikto', 'protected directory', 'web_server'))
    if same_endpoint and same_source and specific_url and gap <= scorer.algorithm.time.default_half_life_seconds and relevant(text_a) and relevant(text_b):
        return ('SAME_ATTACK_STEP', 'MEDIUM',
                'Same scoped source, complete target endpoint and specific HTTP resource/domain, with compatible request-attack detections across distinct observations. Supports investigation correlation; no successful exploit or progression established.')
    ips_a = {x for x in (a.src_ip,a.dst_ip) if x}
    ips_b = {x for x in (b.src_ip,b.dst_ip) if x}
    context_a = {o.entity_id for o in a.entity_occurrences if o.role.value not in ('src_ip','dst_ip')}
    context_b = {o.entity_id for o in b.entity_occurrences if o.role.value not in ('src_ip','dst_ip')}
    if ips_a and ips_b and ips_a.isdisjoint(ips_b) and not (context_a & context_b):
        return ('INCIDENTAL_SIMILARITY', 'MEDIUM',
                'Complete network actors/targets disjoint and no shared extracted non-network context; shared metadata/transport/clock does not establish activity. Unrelated campaign membership is not proven.')
    if gap > scorer.algorithm.candidate.max_window_seconds:
        return ('INCIDENTAL_SIMILARITY', 'MEDIUM',
                'Outside the maximum declared correlation window; partial entity or signature reuse cannot establish continuous activity. Campaign identity remains unknown.')
    return ('UNCERTAIN', 'LOW',
            'Available shared fields do not establish a specific common attack step or progression; benign detector repetition/common infrastructure remain possible.')


def alert_card(a):
    body = a.raw_alert.get('data', a.raw_alert)
    return dict(alert_id=a.alert_id, source=a.source_type.value, source_namespace=a.source_namespace,
        timestamp=str(a.timestamp), src_ip=a.src_ip, dst_ip=a.dst_ip,
        src_port=a.src_port, dst_port=a.dst_port, protocol=body.get('proto',body.get('protocol')),
        signature=a.signature, signature_id=a.rule_id, category=a.category.value,
        severity=a.severity.value, host=a.host, account=a.account,
        process=a.process.model_dump(mode='json') if a.process else None, url=a.url, domain=a.domain,
        other_entities=a.entity_ids, raw_fingerprint=a.raw_fingerprint,
        field_provenance={k:v.model_dump() for k,v in a.field_provenance.items()},
        absence_audit=absence_audit(a), **evidence_profile(field_values(a)))


def make_card(ids, scorer, policy, dataset, strata):
    ids = tuple(sorted(ids))
    a, b = [scorer.index.alerts[i] for i in ids]
    pair = scorer.score_pair(*ids)
    view = diagnostic.state_projection(pair, scorer)
    diagnostic.validate_refs(view, scorer)
    scores = compare(view, policy)
    relation, confidence, reasoning = semantic_review(a, b, scorer, pair)
    states = pair_states(view)
    shared = [dict(entity_id=e, type=scorer.index.entities[e].type.value,
                   value=scorer.index.entities[e].value, scope=scorer.index.entities[e].scope)
              for e in sorted(set(a.entity_ids)&set(b.entity_ids))]
    from app.utils.stable_id import content_digest
    return dict(candidate_id=content_digest(list(ids)), dataset=dataset, pair=list(ids), selection_strata=sorted(strata),
        alert_a=alert_card(a), alert_b=alert_card(b), delta_time=pair.diagnostics['gap_seconds'],
        shared_entities=shared, available_evidence=[k for k,v in states.items() if v['state'] in ('AVAILABLE','PRESENT_BUT_NONMATCHING')],
        matched_evidence=[k for k,v in states.items() if v['state']=='AVAILABLE'],
        unmatched_evidence=[k for k,v in states.items() if v['state']=='PRESENT_BUT_NONMATCHING'],
        unavailable_by_source=[], evidence_states=states, v4_score=pair.score,
        v4_valid=pair.valid, v4_breakdown=scorer.breakdown(pair).model_dump(mode='json'),
        v5_prototype_score=scores['b']['score'], prototypes=scores,
        semantic_relation=relation, semantic_confidence=confidence, reasoning=reasoning,
        review_status='PROVISIONAL_AGENT_RUBRIC_REVIEW', independent_human_review=False,
        correlation_supported=relation in ('SAME_ATTACK_STEP','ATTACK_PROGRESSION'),
        chain_progression_supported=relation=='ATTACK_PROGRESSION',
        ground_truth_used_for_scoring='NO'), view


def ablate(view, family, policy):
    """Diagnostic-only remove support, keeping all original contradictions/guards.
    Facts and their dependency votes must be removed together with dimensions.
    No copied view is ever normalized back into CanonicalAlert.
    """
    v = deepcopy(view)
    def remove(d):
        return (d['family']=='time' if family=='temporal' else
                d['family']=='entity' if family=='entity' else
                d['family']=='behavior' if family=='detector_semantic' else
                d['family']=='relation' if family=='role_evidence' else False)
    names = {d['dimension'] for d in v['dimensions'] if remove(d)}
    for d in v['dimensions']:
        if d['dimension'] in names and d['state']=='SUPPORTED':
            d.update(state='UNOBSERVABLE', strength=0.)
    v['facts'] = [f for f in v['facts'] if f['dimension'] not in names]
    return compare(v, policy)


def replay_view(card):
    """Restore an offline view from a self-contained card for report replay.

    All dimensions/states, fact dependencies and frozen penalties were captured
    at score time. Semantic labels are never read by this function.
    """
    breakdown=card['v4_breakdown'];audit=breakdown['evidence_v2']
    dimensions=deepcopy(audit['dimensions'])
    for dim in dimensions:
        saved=card['evidence_states'][dim['dimension']]
        dim.update(state=saved['diagnostic_state'],v4_state=saved['v4_state'],basis=saved['basis'])
    return dict(dimensions=dimensions,facts=deepcopy(audit['evidence']),
        weights=audit['family_weights'],hard=['frozen_hard_guard'] if 'frozen_hard_guard' in card['prototypes']['a']['gate_reasons'] else [],
        duplicate_risk=audit['duplicate_observation_risk'],
        penalty=card['prototypes']['a']['relation_score']-card['prototypes']['a']['raw_score'],
        v4_score=card['v4_score'],pair=card['pair'],half_life=None)

"""Evidence-only projections and validations. This module never imports a scorer."""
from __future__ import annotations

import base64
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
import re

LABELS = ('CONFIRMED_RELATED', 'PLAUSIBLE_RELATED', 'UNRESOLVED',
          'LIKELY_UNRELATED', 'CONFIRMED_UNRELATED')
FAMILIES = ('TIME', 'SRC_IP', 'DST_IP', 'SRC_PORT', 'DST_PORT', 'PROTOCOL',
    'SIGNATURE', 'SIGNATURE_ID', 'CATEGORY', 'HOST', 'ACCOUNT', 'SESSION',
    'FLOW_ID', 'NETWORK_DIRECTION', 'ENDPOINT_ROLE', 'TOPOLOGY', 'PROCESS',
    'FILE', 'URL', 'HTTP', 'DNS', 'TRANSPORT', 'DETECTOR_TYPE', 'ATTACK_SEMANTIC')
CANONICAL = {'TIME':'timestamp', 'SRC_IP':'src_ip', 'DST_IP':'dst_ip',
    'SRC_PORT':'src_port', 'DST_PORT':'dst_port', 'SIGNATURE':'signature',
    'SIGNATURE_ID':'rule_id', 'CATEGORY':'category', 'HOST':'host',
    'ACCOUNT':'account', 'SESSION':'session', 'PROCESS':'process', 'FILE':'file', 'URL':'url'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode('utf8')).hexdigest()


def present(value):
    return value not in (None, '', 'unknown', [], {})


def pointer(raw, path):
    value = raw
    for part in path.split('/')[1:]:
        part = part.replace('~1','/').replace('~0','~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def decoded_payload(raw):
    payload = raw.get('payload')
    if not payload:
        return None
    try:
        return base64.b64decode(payload, validate=True).decode('utf8', errors='replace')
    except (ValueError, TypeError):
        return None


def fast_log(raw):
    text = raw.get('full_log', '')
    match = re.search(r'\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\].*?\{(\w+)\}\s+(\S+)\s+->\s+(\S+)', text)
    if not match:
        return None
    return dict(gid=match[1], signature_id=match[2], rev=match[3], signature=match[4],
        protocol=match[5], src_endpoint=match[6], dst_endpoint=match[7],
        evidence_pointer='/full_log', diagnostic_only=True)


def raw_facts(raw):
    body = raw.get('data', raw)
    decoded = decoded_payload(raw)
    parsed = fast_log(raw)
    return dict(flow_id=body.get('flow_id'), tx_id=body.get('tx_id'),
        protocol=body.get('proto', body.get('protocol')) or (parsed or {}).get('protocol'),
        http=body.get('http'), tls=body.get('tls'), dns=body.get('dns'),
        fast_log=parsed, payload_decoded=decoded,
        payload_decoded_sha256=hashlib.sha256(decoded.encode()).hexdigest() if decoded else None)


def payload_json(raw):
    text=decoded_payload(raw)
    if not text:
        return None
    # HTTP request headers use CRLF (some historical exports repeat CR).
    match=re.search(r'\{.*\}\s*$',text,re.S)
    if match:
        try:
            value=json.loads(match[0])
            return value if isinstance(value,dict) else None
        except ValueError:
            pass
    return None


def independent_evidence(blind):
    a,b = blind['alert_a'],blind['alert_b']
    ra,rb = raw_facts(a['raw_alert']),raw_facts(b['raw_alert'])
    gap = abs((datetime.fromisoformat(a['timestamp'].replace('Z','+00:00')) -
        datetime.fromisoformat(b['timestamp'].replace('Z','+00:00'))).total_seconds())
    shared = {k:a.get(k) for k in ('src_ip','dst_ip','host','account','session','url','domain')
        if present(a.get(k)) and a.get(k)==b.get(k)}
    conflict = []
    if present(ra['flow_id']) and present(rb['flow_id']) and ra['flow_id'] != rb['flow_id']:
        conflict.append('Different observed flows: excludes identical transport session, not common campaign.')
    if ra['http'] and rb['http'] and ra['http'].get('status') != rb['http'].get('status'):
        conflict.append('HTTP response status differs; inspect the request operations before attributing success.')
    session = []
    if ra['flow_id'] is not None and ra['flow_id']==rb['flow_id']:
        session.append(dict(kind='scoped_flow_equal', flow_id=ra['flow_id'],
            alert_ids=[a['alert_id'],b['alert_id']], tx_ids=[ra['tx_id'],rb['tx_id']]))
    if ra['payload_decoded_sha256'] and ra['payload_decoded_sha256']==rb['payload_decoded_sha256']:
        session.append(dict(kind='byte_equal_decoded_request', sha256=ra['payload_decoded_sha256'],
            warning='Repeated request identity alone does not establish maliciousness.'))
    return dict(temporal=[dict(gap_seconds=gap, timestamps=[a['timestamp'],b['timestamp']])],
        entity=[shared], role=[dict(alert_id=x['alert_id'],src_ip=x.get('src_ip'),dst_ip=x.get('dst_ip'),
            warning='Network source is not automatically the attacker.') for x in (a,b)],
        network=[dict(alert_id=x['alert_id'],src_port=x.get('src_port'),dst_port=x.get('dst_port'),
            protocol=r['protocol']) for x,r in ((a,ra),(b,rb))],
        signature_semantics=[dict(alert_id=x['alert_id'],canonical_signature=x['signature'],
            canonical_rule=x['signature_id'],raw_fast_log=r['fast_log'],http=r['http'])
            for x,r in ((a,ra),(b,rb))], session=session, topology=[], attack_progression=[],
        conflicting_evidence=conflict, decoded_alert_payloads=[dict(alert_id=x['alert_id'],
            pointer='/payload',encoding='base64',text=r['payload_decoded'],
            decoded_sha256=r['payload_decoded_sha256'],diagnostic_only=True)
            for x,r in ((a,ra),(b,rb)) if r['payload_decoded'] is not None])


def semantic_label(blind, annotation):
    """Validate an explicit post-inspection decision; no numeric algorithm input."""
    if set(blind) != {'pair_id','dataset','alert_a','alert_b'}:
        raise ValueError('blind_evidence_only')
    if annotation['blind_sha256'] != digest(blind):
        raise ValueError('annotation_not_bound_to_raw_evidence')
    if annotation['pair_id'] != blind['pair_id'] or annotation['label'] not in LABELS:
        raise ValueError('invalid_annotation')
    if not annotation['reason'] or not annotation['reviewed_raw_alert_ids'] == [
            blind['alert_a']['alert_id'],blind['alert_b']['alert_id']]:
        raise ValueError('missing_raw_review')
    return dict(label=annotation['label'],confidence=annotation['confidence'],reason=annotation['reason'],
        attack_semantic_support=annotation['attack_semantic_support'],score_used_for_label=False,
        review_status='COMPLETED_AGENT_EVIDENCE_ADJUDICATION',independent_human_review=False,
        annotation_sha256=digest(annotation),observed_relation=annotation['observed_relation'])


def precision_evidence(cards):
    counts = Counter(x['adjudication']['label'] for x in cards)
    denominator = len(cards)-counts['UNRESOLVED']
    strict = counts['CONFIRMED_RELATED']
    broad = strict+counts['PLAUSIBLE_RELATED']
    return dict(metric_name='review-set admitted precision evidence',total=len(cards),
        counts={k:counts[k] for k in LABELS},adjudicable=denominator,unresolved=counts['UNRESOLVED'],
        strict_numerator=strict,broad_numerator=broad,negative_count=counts['LIKELY_UNRELATED']+counts['CONFIRMED_UNRELATED'],
        strict=strict/denominator if denominator else None,broad=broad/denominator if denominator else None,
        metric_status='available' if denominator else 'not_applicable',
        limitation='Selected set; unresolved excluded, never negatives. A tiny adjudicable denominator cannot validate admission precision.')


def observations(alert):
    """Inspect canonical provenance + declared raw structures, never external logs.

    Attached free text is retained in samples. Zero structured observations do
    not exclude information in snippets or establish vendor-wide incapability.
    """
    a = alert.model_dump(mode='json')
    raw = a['raw_alert']
    facts = raw_facts(raw)
    body = raw.get('data', raw)
    prefix = '/data' if 'data' in raw else ''
    result = {}
    for family,field in CANONICAL.items():
        value = a.get(field)
        if present(value):
            prov = a['field_provenance'].get(field)
            if prov:
                result[family] = dict(value=value,pointer=prov['raw_pointer'],
                    canonical_field=field,canonical_value=value,
                    qualification='mapped_detector_category' if family=='CATEGORY' else 'observed_field')
    # Structured extensions retained in raw_alert; no new canonical fields.
    for family,key in [('FLOW_ID','flow_id'),('PROTOCOL','proto'),('HTTP','http'),('DNS','dns')]:
        if present(body.get(key)):
            result[family] = dict(value=body[key],pointer=prefix+'/'+key,
                canonical_field=None,canonical_value=None,qualification='raw_extension_only')
    if 'PROTOCOL' not in result and facts['fast_log']:
        result['PROTOCOL'] = dict(value=facts['protocol'],pointer='/full_log',
            canonical_field=None,canonical_value=None,qualification='diagnostic_snippet_parse')
    if facts['fast_log']:
        for family,key in [('SRC_PORT','src_endpoint'),('DST_PORT','dst_endpoint')]:
            endpoint=facts['fast_log'][key]
            match=re.search(r':(\d+)$',endpoint)
            if family not in result and match and 0<=int(match[1])<=65535:
                result[family]=dict(value=int(match[1]),pointer='/full_log',canonical_field=None,
                    canonical_value=None,qualification='diagnostic_snippet_parse')
    body_json=payload_json(raw)
    if body_json:
        for family,key in [('ACCOUNT','email'),('SESSION','token')]:
            if family not in result and present(body_json.get(key)):
                result[family]=dict(value=body_json[key],pointer='/payload',canonical_field=None,
                    canonical_value=None,qualification='diagnostic_base64_request_json:'+key+
                    '; application hostname scopes identity; request claim is not successful authentication')
    if 'SRC_IP' in result and 'DST_IP' in result:
        result['ENDPOINT_ROLE'] = dict(value={'src':a['src_ip'],'dst':a['dst_ip']},
            pointer=result['SRC_IP']['pointer'],additional_pointer=result['DST_IP']['pointer'],
            canonical_field='src_ip,dst_ip',canonical_value=[a['src_ip'],a['dst_ip']],
            qualification='packet_endpoint_roles_only_not_attacker_or_victim')
    if all(k in result for k in ('SRC_IP','DST_IP','SRC_PORT','DST_PORT','PROTOCOL')):
        result['TRANSPORT'] = dict(value={k:result[k]['value'] for k in
            ('SRC_IP','DST_IP','SRC_PORT','DST_PORT','PROTOCOL')},pointer=result['PROTOCOL']['pointer'],
            canonical_field='endpoint_bundle',canonical_value=[a['src_ip'],a['dst_ip'],a['src_port'],a['dst_port']],
            qualification='complete_transport_tuple')
    if a['relations']:
        ref=a['relations'][0]['raw_pointers'][0]
        result['TOPOLOGY']=dict(value=a['relations'],pointer=ref['pointer'],canonical_field='relations',
            canonical_value=a['relations'],qualification='field_attested_relation')
    detector_path = '/AnalysisComponent/AnalysisComponentType' if 'AnalysisComponent' in raw else (
        '/decoder/name' if 'decoder' in raw else '/event_type')
    try:
        value = pointer(raw, detector_path)
    except (KeyError, TypeError, IndexError):
        value = None
    if present(value):
        result['DETECTOR_TYPE']=dict(value=value,pointer=detector_path,canonical_field='alert_type',
            canonical_value=a.get('alert_type'),qualification='detector_metadata')
    # Capability to carry attack semantics != proof that every detection is true.
    decoded = facts['payload_decoded'] or ''
    attack = attack_action(a.get('url'), decoded)
    if attack:
        p = '/payload' if facts['payload_decoded'] else a['field_provenance']['url']['raw_pointer']
        result['ATTACK_SEMANTIC']=dict(value=attack,pointer=p,canonical_field='url',
            canonical_value=a.get('url'),qualification='explicit_attempt_content_not_success')
    return result


def attack_action(url, payload):
    """Content tags for post-hoc directed search; never nomination/scoring features."""
    text=(url or '')+'\n'+payload
    low=text.lower()
    if ('cmd.exe' in low and ('/c+' in low or '/c%' in low)) or re.search(r'(?:[?&])cmd=',low):
        return 'COMMAND_EXECUTION_ATTEMPT'
    if 'select' in low and ('union' in low or 'all_users' in low or '/**/' in low):
        return 'SQL_QUERY_INJECTION_ATTEMPT'
    if '/etc/shadow' in low or '/etc/passwd' in low or '/_vti_pvt/' in low:
        return 'SENSITIVE_FILE_ACCESS_ATTEMPT'
    if '<script>' in low or '%3cscript' in low:
        return 'SCRIPT_INJECTION_ATTEMPT'
    if 'phpinfo' in low:
        return 'SERVER_INFORMATION_PROBE'
    return None


def capability_rows(entries):
    grouped=defaultdict(list)
    for dataset,alert,locator in entries:
        raw=alert.raw_alert
        profile=(raw.get('AnalysisComponent',{}).get('AnalysisComponentType') or
                 raw.get('decoder',{}).get('name') or raw.get('event_type') or 'unknown')
        grouped[(dataset,alert.source_namespace,alert.source_type.value,profile)].append((alert,locator))
    rows=[]
    for (dataset,namespace,source_type,profile),members in sorted(grouped.items()):
        per_alert=[(a,loc,observations(a)) for a,loc in members]
        total=len(members)
        for family in FAMILIES:
            hits=[(a,loc,f[family]) for a,loc,f in per_alert if family in f]
            count=len(hits)
            samples=[]
            for a,loc,f in hits[:3]:
                raw_value=pointer(a.raw_alert,f['pointer'])
                samples.append(dict(alert_id=a.alert_id,raw_fingerprint=a.raw_fingerprint,locator=loc,
                    raw_evidence=dict(pointer=f['pointer'],value=raw_value),canonical_evidence=dict(
                        field=f['canonical_field'],value=f['canonical_value']),interpreted_value=f['value'],
                    qualification=f['qualification'],**({'additional_raw_evidence':dict(
                        pointer=f['additional_pointer'],value=pointer(a.raw_alert,f['additional_pointer']))}
                        if 'additional_pointer' in f else {})))
            # No unmeasured reliability threshold is invented. Full valid coverage
            # attests this finite export; partial observations remain conditional.
            status='ATTESTED' if count==total else 'PARTIAL' if count else 'UNAVAILABLE'
            rows.append(dict(source=namespace,source_type=source_type,detector_profile=profile,dataset=dataset,
                family=family,schema_supported=True if family in CANONICAL else None,
                schema_support_scope='CanonicalAlert schema; adapter/raw capability separately observed',
                observed=count,total=total,coverage=count/total,
                reliability='HIGH_IN_OBSERVED_EXPORT' if count==total else 'CONDITIONAL' if count else 'N/A',
                reliably_observed=count==total,semantically_usable=bool(count),
                semantic_scope=('detector/request intent only, not compromise' if family=='ATTACK_SEMANTIC' else
                    'packet src/dst only; no adversary attribution' if family=='ENDPOINT_ROLE' else
                    'scoped flow identity, not application session' if family=='FLOW_ID' else 'observed field only'),
                status=status,observation_state='SEMANTICALLY_USABLE' if count else 'NOT_AVAILABLE',
                capability_state='OBSERVED' if count else 'UNKNOWN',source_cannot_provide=False,
                absence_scope=None if count else 'No value in inspected structured fields of this frozen export; snippets may contain unextracted context.',
                sample_alert_ids=[s['alert_id'] for s in samples],evidence=samples))
    return rows


def capability_comparison(left, right, left_capability, right_capability):
    if present(left) and present(right):
        return 'OBSERVABLE_MATCH' if left==right else 'OBSERVABLE_NONMATCH'
    if 'CAPABILITY_ABSENT' in (left_capability,right_capability):
        return 'CAPABILITY_ABSENT'
    return 'UNKNOWN'


def failure_stage(edge):
    if not edge['RAW_VISIBLE']:
        return 'SOURCE_OBSERVABILITY'
    if not edge['CANONICAL_VISIBLE']:
        return 'CANONICALIZATION'
    if not edge['CANDIDATE_NOMINATED']:
        return 'CANDIDATE_NOMINATION'
    if not edge['SCORED']:
        return 'SCORING'
    if not edge.get('gate_passed',True):
        return 'EVIDENCE_GATE'
    return 'THRESHOLD' if not edge['ADMITTED'] else 'NONE'


def validate_progression(package):
    alerts=package['alerts']; edges=package['edges']
    if len(alerts)<3 or len(set(alerts))!=len(alerts) or len(edges)!=len(alerts)-1:
        raise ValueError('at_least_three_distinct_alerts_two_edges_required')
    for index,edge in enumerate(edges):
        if (edge['from'],edge['to'])!=(alerts[index],alerts[index+1]):
            raise ValueError('disconnected_edge_adjacency')
        if edge['semantic_label']!='CONFIRMED_RELATED' or not edge.get('direction_grounded'):
            raise ValueError('semantic_and_order_proof_required')
    return True

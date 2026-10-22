"""Exhaustive pair review plus existing identity buckets; no transitive union."""
from collections import defaultdict
from itertools import combinations
from .models import Proposal

def generate(s):
    proposals={}
    def add(members, reason, identity_kind=None):
        members=tuple(sorted(set(members)))
        if not members: return
        proposals.setdefault((members,identity_kind),set()).add(reason)
    ids=sorted(s.indexes['stage'])
    for sid in ids: add([sid],'SINGLE_STAGE_REVIEW')
    # Small offline audit: review every pair, including explicitly unknown ones.
    # Pair existence is not a semantic assertion and never implies acceptance.
    for a,b in combinations(ids,2): add([a,b],'EXHAUSTIVE_PAIR_REVIEW')
    for d in s.indexes['relation_decision'].values():
        add([d['stage_a_id'],d['stage_b_id']], 'EXISTING_'+d['relation_type'])
    for c in s.indexes['context_posting'].values():
        if len(c['stage_ids'])>1: add(c['stage_ids'],'EXISTING_'+c['context_type']+'_BUCKET')
    buckets=defaultdict(set)
    for sid,st in s.indexes['stage'].items():
        for field in ['flow_bindings','session_bindings','request_bindings','task_bindings']:
            for key in st[field]: buckets[(field,key)].add(sid)
    for (field,_),members in sorted(buckets.items()):
        if len(members)>1:
            add(members,'EXISTING_'+field.upper()+'_BUCKET')
            if field=='request_bindings': add(members,'EXPLICIT_SAME_REQUEST_REVIEW','request')
    # All stages attested by the SAME existing P1 identity are evaluated as a
    # whole proposal. This is an identity bucket, not relation connectivity.
    request_groups=defaultdict(set)
    from .models import jcs
    for c in s.indexes['claim'].values():
        if c['evidence_type']=='REQUEST_RESPONSE':
            request_groups[jcs(c['identity'])].update([c['stage_a_id'],c['stage_b_id']])
    for members in request_groups.values(): add(members,'EXISTING_REQUEST_RESPONSE_IDENTITY','request')
    return [Proposal(m,tuple(sorted(r)),kind) for (m,kind),r in
            sorted(proposals.items(),key=lambda x:(x[0][0],x[0][1] or ''))]


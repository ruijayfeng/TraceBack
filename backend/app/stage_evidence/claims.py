"""Collect logical facts once and normalize every supporting observation."""
from collections import defaultdict
import json

from app.models.alerts import EvidencePointer
from app.utils.stable_id import canonical_json
from .config import CONTEXT_TYPES, DIRECTIONAL, DIRECT_ASSOCIATIVE
from .contracts import (ContextIdentityPosting, ContextMembership, EvidenceClaim,
    EvidenceTraceIndex, ObservationValidation, RawEvidenceReference,
    SupportingObservation, claim_key, context_id, stable)


class ClaimCollector:
    def __init__(self,alerts,stages):
        self.alerts,self.stages=alerts,stages
        self.pointers,self.validations,self.observations,self.groups={},{},{},{}
        self.contexts={}

    def pointer(self,pointer):
        pointer.resolve(self.alerts)
        data=pointer.model_dump(mode='json')
        pid=stable('erp',data)
        if pid not in self.pointers:
            self.pointers[pid]=RawEvidenceReference(pointer_id=pid,raw_pointer=pointer)
        return pid

    def build_contexts(self,indexes,entities,policy):
        groups={}
        for sid,index in sorted(indexes.items()):
            for bucket in index.values():
                for item in bucket:
                    if item.kind not in CONTEXT_TYPES:
                        continue
                    ctype,etype=CONTEXT_TYPES[item.kind]
                    if etype not in policy.enabled_evidence_types:
                        continue
                    identity=json.loads(item.identity)
                    cid=context_id(ctype,identity)
                    group=groups.setdefault(cid,dict(context_type=ctype,identity=identity,etype=etype,members=defaultdict(set)))
                    for pointer in item.pointers:
                        group['members'][(sid,item.alert_id,item.role)].add(self.pointer(EvidencePointer(alert_id=item.alert_id,pointer=pointer,side='shared')))
        for cid,group in sorted(groups.items()):
            members=[ContextMembership(stage_id=sid,alert_id=aid,role=role,raw_pointer_ids=sorted(refs)) for (sid,aid,role),refs in sorted(group['members'].items())]
            aids=sorted({m.alert_id for m in members})
            sids=sorted({m.stage_id for m in members})
            identity=group['identity']
            if group['context_type']=='PROCESS':
                entity=entities.get(identity.get('process'))
                complete=bool(entity and entity.type.value=='PROCESS' and entity.scope)
                processes=[getattr(self.alerts[m.alert_id],m.role) for m in members]
                complete=complete and all(p and (p.guid or p.instance_id or (p.pid is not None and p.start_time)) for p in processes)
                polluted=any(len({getattr(p,field) for p in processes if p and getattr(p,field) is not None})>1 for field in ('pid','start_time','guid','instance_id'))
            elif group['context_type']=='OBJECT':
                entity=entities.get(identity.get('host'))
                complete=bool(entity and entity.type.value=='HOST' and entity.scope and identity.get('value'))
                polluted=False
            elif group['context_type']=='FLOW':
                complete=bool(identity.get('scope') and identity.get('native_id') and
                    all(identity.get('tuple',{}).get(k) is not None for k in ('src_ip','src_port','dst_ip','dst_port','protocol')))
                polluted=False
            else:
                complete=bool(identity.get('scope') and identity.get('value') and identity.get('subtype'))
                polluted=False
            times=[self.alerts[aid].timestamp for aid in aids]
            # Parent-only mentions certify lineage, not current-process usage.
            # Preserve every membership, but measure direct identity exclusivity
            # over the roles used by SAME_PROCESS_INSTANCE claims.
            direct_sids = sorted({m.stage_id for m in members if m.role == 'process'}) if group['context_type']=='PROCESS' else sids
            self.contexts[cid]=ContextIdentityPosting(context_identity_id=cid,context_type=group['context_type'],
                scoped_identity=identity,stage_ids=sids,alert_ids=aids,
                source_namespaces=sorted({self.alerts[aid].source_namespace for aid in aids}),
                first_seen=min(times),last_seen=max(times),evidence_claim_ids=[],memberships=members,
                metadata=dict(identity_complete=bool(complete),identity_polluted=polluted,
                    exclusive_direct_eligible=bool(complete and not polluted and len(direct_sids)==2 and group['etype'] in policy.exclusive_context_evidence_types),
                    direct_policy=policy.exclusive_context_policy,
                    direct_membership_roles=['process'] if group['context_type']=='PROCESS' else ['all'],
                    semantic_basis='global_membership_only; never an all-pairs direct relation'))

    def add(self,a,b,kind,left,right,direction,refs,time,issues,reason,identity):
        for sid,aid in ((a.stage_id,left.alert_id),(b.stage_id,right.alert_id)):
            if aid not in self.stages[sid].alert_ids:
                raise ValueError('claim_support_observation_outside_stage')
        if {p.alert_id for p in refs}!={left.alert_id,right.alert_id}:
            raise ValueError('claim_requires_both_raw_witnesses')
        check=dict(temporal_check=time,conflict_status=issues,valid=not issues)
        vid=stable('evc',check)
        if vid not in self.validations:
            self.validations[vid]=ObservationValidation(validation_id=vid,**check)
        observation_data=dict(alert_a_id=left.alert_id,alert_b_id=right.alert_id,
            raw_pointer_ids=sorted({self.pointer(p) for p in refs}),validation_id=vid)
        oid=stable('obs',observation_data)
        if oid not in self.observations:
            self.observations[oid]=SupportingObservation(observation_id=oid,**observation_data)
        full_identity=dict(identity)
        if left.identity!=right.identity:
            full_identity['conflicting_endpoint_identity']=json.loads(right.identity)
        # A lineage claim identifies BOTH P and Q. Distinct children cannot be
        # accidentally merged merely because they have the same parent key.
        if kind=='PARENT_CHILD_PROCESS':
            child=self.alerts[right.alert_id if direction=='A_TO_B' else left.alert_id]
            full_identity['child_process_entities']=sorted(o.entity_id for o in child.entity_occurrences if o.role.value=='process')
            if not full_identity['child_process_entities']:
                full_identity['unbound_child_facts']=child.process.model_dump(mode='json') if child.process else None
        directional_roles={'PARENT_CHILD_PROCESS':('PARENT','CHILD'),'REQUEST_RESPONSE':('REQUEST','RESPONSE'),
            'OBJECT_CREATE_EXECUTE':('CREATE','EXECUTE_OR_CONSUME'),'OBJECT_HANDOFF':('PRODUCE','CONSUME'),
            'AUTH_ESTABLISH_USE':('ESTABLISH','USE'),'EXPLICIT_ATTESTED_RELATION':('PREDECESSOR','SUCCESSOR')}
        directional_roles['CONNECTION_ESTABLISH_ACCEPT']=('INITIATE','ACCEPT')
        if kind in directional_roles:
            roles=directional_roles[kind] if direction=='A_TO_B' else tuple(reversed(directional_roles[kind]))
        else:
            roles=(left.role or 'MEMBER',right.role or 'MEMBER')
        key=claim_key(a.stage_id,b.stage_id,kind,full_identity,direction,*roles)
        claim_id=stable('ecl',key)
        group=self.groups.setdefault(claim_id,dict(key=key,reason=reason,observation_ids=set(),projection_identity=identity,
            projection_roles=[left.role,right.role]))
        group['observation_ids'].add(oid)
        return claim_id

    def finish(self):
        claims=[]
        context_claims=defaultdict(list)
        for claim_id,group in sorted(self.groups.items()):
            key=group['key']
            oids=sorted(group['observation_ids'])
            checks=[self.validations[self.observations[oid].validation_id] for oid in oids]
            valid=[c for c in checks if c.valid]
            conflicts=sorted({p for c in checks for p in c.conflict_status})
            kind=key['evidence_type']
            cid=None
            semantic='SUPPORTING'
            if kind in DIRECTIONAL:
                semantic='DIRECTIONAL_RELATION'
            elif kind in DIRECT_ASSOCIATIVE:
                semantic='DIRECT_ASSOCIATIVE_RELATION'
            else:
                matching=[ctype for ctype,etype in CONTEXT_TYPES.values() if etype==kind]
                if matching:
                    candidate=context_id(matching[0],group['projection_identity'])
                    posting=self.contexts.get(candidate)
                    if posting and {key['stage_a_id'],key['stage_b_id']}<=set(posting.stage_ids):
                        cid=candidate
                        context_claims[cid].append(claim_id)
                    posting=self.contexts.get(cid)
                    eligible = posting and posting.metadata['exclusive_direct_eligible']
                    if eligible and posting.context_type=='PROCESS':
                        eligible = {key['stage_a_id'],key['stage_b_id']} == {m.stage_id for m in posting.memberships if m.role=='process'}
                    semantic='DIRECT_ASSOCIATIVE_RELATION' if eligible else 'CONTEXT'
            unique_checks={canonical_json(c.temporal_check):c.temporal_check for c in valid or checks}
            temporal=next(iter(unique_checks.values())) if len(unique_checks)==1 else dict(status='CONSISTENT' if valid else 'CONFLICT',
                rule='see_each_supporting_observation_validation',valid_observation_count=len(valid),invalid_observation_count=len(checks)-len(valid))
            claims.append(EvidenceClaim(claim_id=claim_id,**key,semantic_class=semantic,valid=bool(valid),
                temporal_check=temporal,conflict_status=[] if valid else conflicts,reason=group['reason'],
                observation_ids=oids,observation_count=len(oids),context_identity_id=cid,
                metadata=dict(projection_identity=group['projection_identity'],invalid_observation_count=len(checks)-len(valid),
                    **({'projection_roles':group['projection_roles']} if group['projection_roles']!=[key['role_a'],key['role_b']] else {}),
                    observation_conflicts=conflicts,semantic_basis='typed_relation' if semantic=='DIRECTIONAL_RELATION' or kind in DIRECT_ASSOCIATIVE else
                    'exclusive_two_stage_complete_identity' if semantic=='DIRECT_ASSOCIATIVE_RELATION' else 'context_membership' if semantic=='CONTEXT' else 'supporting_context')))
        contexts=[posting.model_copy(update=dict(evidence_claim_ids=sorted(context_claims[cid]))) for cid,posting in sorted(self.contexts.items())]
        trace=EvidenceTraceIndex(raw_pointers=[self.pointers[k] for k in sorted(self.pointers)],
            validations=[self.validations[k] for k in sorted(self.validations)],observations=[self.observations[k] for k in sorted(self.observations)])
        return claims,contexts,trace

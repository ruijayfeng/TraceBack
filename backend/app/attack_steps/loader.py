"""Read existing formal snapshots, verify provenance and reference closure only."""
import json
from pathlib import Path
import re

# Serialization primitive only. No Stage/Relation/Chain builder is imported.
from app.utils.stable_id import content_digest
from app.models.base import resolve_pointer
from .models import Snapshot, PrototypeError, VERSIONS, index, require, sha

def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key:' + key)
        result[key] = value
    return result

def read_json(path):
    return json.loads(Path(path).read_text('utf-8-sig'), object_pairs_hook=no_duplicate_keys,
                      parse_constant=lambda x: (_ for _ in ()).throw(PrototypeError('nonfinite_json:' + x)))

def file_digests(files):
    return {k: sha(Path(v).read_bytes()) for k, v in files.items()}

def signature(s):
    return content_digest(dict(stage8=s.stage8, stage9=s.stage9))

def pointer(s, ref):
    require(set(ref) >= {'alert_id','pointer','side'}, 'invalid_evidence_pointer')
    require(ref['side'] in {'src','dst','shared'}, 'invalid_pointer_side')
    # Reuse the actual upstream resolver, including valid empty-root pointers
    # and preserved raw-key NFC lookup. This is resolution, not recomputation.
    return resolve_pointer(s.indexes['alert'][ref['alert_id']]['raw_alert'],ref['pointer'])

def build_indexes(s):
    a, n = s.stage8, s.stage9
    e = a['evidence']; t = e['trace']; p = a['identity_projection']
    s.indexes = {
        'stage':index(a['stages']['stages'],'stage_id'),
        'alert':index(a['alerts'],'alert_id'), 'entity':index(a['entities'],'entity_id'),
        'behavior_annotation':index(a['stages']['behaviors'],'alert_id'),
        'community':index(a['communities']['incident_candidates'],'community_id'),
        'chain':index(n['chains'],'chain_id'),
        'relation_decision':index(e['decisions'],'candidate_id'),
        'claim':index(e['claims'],'claim_id'),
        'observation':index(t['observations'],'observation_id'),
        'validation':index(t['validations'],'validation_id'),
        'raw_pointer':index(t['raw_pointers'],'pointer_id'),
        'context_posting':index(e['context_postings'],'context_identity_id'),
        'host_alias_binding':index(p['host_alias_bindings'],'alias_binding_id'),
        'auth_session_binding':index(p['auth_session_bindings'],'projection_id'),
        'context_binding':index(p['context_bindings'],'projection_id')}

def validate_source(s):
    """Validate existing objects; never rebuild upstream stages or chains."""
    a, n, i = s.stage8, s.stage9, s.indexes
    for key, name in [('communities','community'),('stages','stages'),('candidates','candidates'),('evidence','evidence')]:
        require(a[key]['contract_version'] == VERSIONS[name], 'unsupported_contract:' + name)
        require(re.fullmatch('[0-9a-f]{64}',a[key]['config_hash']) is not None, 'missing_config_hash')
    require(n['contract_version'] == VERSIONS['chains'], 'unsupported_chain_contract')
    owner={}; chain_owner={}
    for sid, stage in i['stage'].items():
        require(stage['community_id'] in i['community'], 'missing_community')
        require(stage['alert_ids'] and len(stage['alert_ids']) == stage['alert_count'], 'stage_size_mismatch')
        for aid in stage['alert_ids']:
            require(aid not in owner and aid in i['alert'] and aid in i['behavior_annotation'], 'stage_alert_partition_invalid')
            require(i['alert'][aid].get('raw_alert') is not None, 'missing_raw_alert')
            require(aid in i['community'][stage['community_id']]['alert_ids'], 'stage_community_member_mismatch')
            owner[aid]=sid
        for key in ['host_entities','account_entities','process_entities']:
            require(not set(stage[key])-i['entity'].keys(), 'dangling_stage_entity')
        for basis in stage['aggregation_basis']:
            for ref in basis['evidence']: pointer(s,ref)
    require(set(owner)==set(i['alert']), 'incomplete_stage_population')
    accepted={rid:d for rid,d in i['relation_decision'].items() if d['relation_type']!='NO_RELATION'}
    for rid,d in i['relation_decision'].items():
        x,y=d['stage_a_id'],d['stage_b_id']
        require(x<y and x in i['stage'] and y in i['stage'], 'invalid_relation_pair')
        require(d['relation_type'] in {'DIRECTED_EDGE','UNDIRECTED_EDGE','NO_RELATION'}, 'unknown_relation_type')
        if d['relation_type']=='DIRECTED_EDGE':
            require((d['from_stage_id'],d['to_stage_id'])==({'A_TO_B':(x,y),'B_TO_A':(y,x)}.get(d['direction_claim'])), 'invalid_relation_direction')
        else:
            require(d['from_stage_id'] is None and d['to_stage_id'] is None and
                    d['direction_claim']==('NONE' if d['relation_type']=='NO_RELATION' else 'UNDIRECTED'), 'fabricated_direction')
        for field in ['relation_claim_ids','context_claim_ids','supporting_claim_ids','invalid_claim_ids']:
            for cid in d[field]:
                c=i['claim'][cid]
                require((c['stage_a_id'],c['stage_b_id'])==(x,y), 'claim_pair_mismatch')
        require(bool(d['primary_claim_id'])==(rid in accepted), 'invalid_primary_claim')
        if rid in accepted:
            require(d['primary_claim_id'] in d['relation_claim_ids'], 'missing_primary_claim')
        for cid in d['context_identity_ids']: i['context_posting'][cid]
    for row in i['raw_pointer'].values(): pointer(s,row['raw_pointer'])
    for ob in i['observation'].values():
        i['validation'][ob['validation_id']]
        require({i['raw_pointer'][pid]['raw_pointer']['alert_id'] for pid in ob['raw_pointer_ids']} ==
                {ob['alert_a_id'],ob['alert_b_id']}, 'observation_pointer_witness_mismatch')
    for c in i['claim'].values():
        for oid in c['observation_ids']:
            ob=i['observation'][oid]
            for side in ['a','b']:
                require(ob['alert_'+side+'_id'] in i['stage'][c['stage_'+side+'_id']]['alert_ids'], 'claim_witness_outside_stage')
    for ctx in i['context_posting'].values():
        for m in ctx['memberships']:
            require(m['alert_id'] in i['stage'][m['stage_id']]['alert_ids'], 'context_witness_outside_stage')
            for pid in m['raw_pointer_ids']:
                require(i['raw_pointer'][pid]['raw_pointer']['alert_id']==m['alert_id'], 'context_pointer_witness_mismatch')
    all_binding_ids=set().union(*(set(i[k]) for k in ['host_alias_binding','auth_session_binding','context_binding']))
    for al in i['alert'].values():
        require(not set(al.get('identity_binding_ids',[]))-all_binding_ids, 'dangling_identity_binding')
        for occurrence in al['entity_occurrences']:
            require(occurrence['entity_id'] in i['entity'], 'dangling_entity_occurrence')
    relation_owners=[]
    for cid,ch in i['chain'].items():
        require(ch['stage_ids'] and ch['single_stage']==(len(ch['stage_ids'])==1), 'invalid_chain_membership')
        require(ch['entry_exit_basis']=='existing_directed_relations_only' and ch['weak_direction_is_causal'] is False, 'invalid_chain_semantics')
        require(not set(ch['entry_stage_ids']+ch['exit_stage_ids'])-set(ch['stage_ids']), 'invalid_chain_entry_exit')
        for sid in ch['stage_ids']:
            require(sid in i['stage'] and sid not in chain_owner, 'chain_stage_partition_invalid')
            chain_owner[sid]=cid
        for rid in ch['relation_ids']:
            d=accepted[rid]
            require({d['stage_a_id'],d['stage_b_id']} <= set(ch['stage_ids']), 'chain_relation_outside_members')
            relation_owners.append(rid)
    require(set(chain_owner)==set(i['stage']), 'missing_chain_stage')
    require(len(relation_owners)==len(set(relation_owners)) and set(relation_owners)==set(accepted), 'chain_relation_partition_invalid')
    i['stage_owner']=owner; i['chain_owner']=chain_owner; i['accepted']=accepted
    # Compute the existing formal signature, without executing reconstruction.
    payload=dict(stages={k:v for k,v in sorted(i['stage'].items())},
        relations={k:v for k,v in sorted(accepted.items())}, decisions=a['evidence']['decisions'],
        evidence=a['evidence'],alerts={k:v for k,v in sorted(i['alert'].items())},legacy_input=None)
    require(content_digest(payload)==n['input_digest']==s.receipt['graph_input_digest'], 'graph_input_digest_mismatch')

def load_inputs(files):
    files={k:Path(v).resolve() for k,v in files.items()}
    require(len(set(files.values()))==len(files), 'input_paths_must_be_distinct')
    forbidden={'ground_truth','evaluation'}
    for path in files.values():
        require(not any(part.casefold() in forbidden or part.casefold().startswith(('gt_stage','gt_relation','gt_stage_fragment','cross_gt_','review_evidence_'))
                        for part in path.parts),'forbidden_input_role_path')
    require(files['stage8'].name=='stage8.json' and files['stage9'].name=='stage9.json' and
            files['receipt'].name=='receipt.json' and len({files[k].parent for k in ['stage8','stage9','receipt']})==1,
            'formal_artifact_pair_required')
    digests=file_digests(files)
    manifest=read_json(files['freeze_manifest'])
    for name,digest in manifest.items():
        # Match only the named, frozen document paths supplied by the CLI.
        for key in ['contract','schema']:
            if Path(name.replace('\\','/')).name==files[key].name:
                require(digests[key]==digest, 'frozen_contract_modified:' + key)
    require(all(any(Path(k.replace('\\','/')).name==files[n].name for k in manifest)
                for n in ['contract','schema']), 'incomplete_freeze_manifest')
    rc=read_json(files['receipt']); provenance=read_json(files['provenance'])
    require(provenance['contract_version']=='attack-step-provenance-v1.1','invalid_provenance_version')
    require(set(provenance)=={'contract_version','dataset_version','dataset_sha256','producer','version_source'}, 'invalid_provenance_fields')
    for key in ['dataset_version','producer']:
        require(isinstance(provenance[key],str) and provenance[key].strip(), 'missing_provenance:' + key)
    source=provenance['version_source']
    require(set(source)=={'kind','reference'} and source['kind'] in {'PRODUCER_RELEASE','IMMUTABLE_DATASET_MANIFEST'} and
            isinstance(source['reference'],str) and source['reference'].strip(), 'invalid_version_source')
    serialized=json.dumps(provenance).casefold()
    require(not any(t in serialized for t in ['ground_truth','gt_stage','gt-s0','evaluation','fragment_mapping']), 'gt_provenance_denied')
    for name in ['stage8','stage9']:
        require(digests[name]==rc[name+'_sha256'], 'input_sha_mismatch:' + name)
    require(digests['dataset']==rc['input_sha256']==provenance['dataset_sha256'], 'dataset_sha_mismatch')
    require(rc['relation_id_field']=='candidate_id', 'unsupported_relation_identity')
    s=Snapshot(read_json(files['stage8']),read_json(files['stage9']),rc,provenance,
               digests,read_json(files['schema']),digests['contract'],files)
    try:
        build_indexes(s); validate_source(s)
    except (KeyError,IndexError,TypeError) as exc:
        raise PrototypeError('input_reference_or_required_field_missing:' + str(exc)) from exc
    s.original_signature=signature(s)
    return s

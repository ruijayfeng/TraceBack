"""Annotate accepted original relations; never construct semantic edges."""
def membership_index(s,groups):
    result=[]
    for sid in sorted(s.indexes['stage']):
        confirmed=[g['semantic_step_id'] for g in groups if g['membership_status']=='CONFIRMED' and sid in g['member_stage_ids']]
        if len(confirmed)>1: raise ValueError('duplicate_primary_membership')
        result.append(dict(stage_id=sid,original_chain_id=s.indexes['chain_owner'][sid],
            primary_semantic_step_id=confirmed[0] if confirmed else None,
            candidate_group_ids=sorted(g['semantic_step_id'] for g in groups if g['membership_status']!='CONFIRMED' and sid in g['member_stage_ids'])))
    return result

def project(s,membership):
    primary={row['stage_id']:row['primary_semantic_step_id'] for row in membership}
    return [dict(source_relation_id=rid,**{key:d[key] for key in [
        'relation_type','stage_a_id','stage_b_id','direction_claim','from_stage_id','to_stage_id']},
        stage_a_primary_semantic_step_id=primary[d['stage_a_id']],
        stage_b_primary_semantic_step_id=primary[d['stage_b_id']]) for rid,d in sorted(s.indexes['accepted'].items())]

"""A–G: read historical, sealed results; never change inputs or production code."""
from collections import Counter
from datetime import datetime
from . import ROOT, OUT, BASE, INPUT
from evaluation.framework.formula_design.runtime import read, rows, save, sha


def run():
    if (OUT/'audit_complete.json').exists():
        raise ValueError('audit_already_written')
    from evaluation.framework.semantics_final.runtime import verify_freeze, verify_seal
    frozen = verify_freeze(); verify_seal()
    alerts = {r['alert_id']: r for r in rows(INPUT/'canonical.jsonl.gz')}
    projection = read(BASE/'evaluation/label_projection.json')
    hard = set(projection['hard_ids']); attack = set(projection['attack_ids'])
    negatives = [r for r in rows(BASE/'blind/members.jsonl.gz')
                 if (set(r['support_pair']) & hard and set(r['support_pair']) & attack)]
    negatives.sort(key=lambda r: (-r['score'], r['support_pair']))
    chosen = negatives[:20]
    gt = read(BASE/'ground_truth_edge_scores.json')['edges']
    wanted = {tuple(sorted(r['support_pair'])) for r in chosen}
    wanted.update(tuple(sorted((r['source_alert_id'], r['target_alert_id']))) for r in gt.values())
    details = {}
    for r in rows(BASE/'blind/diagnostics.jsonl.gz'):
        if r['stage'] == 'member_score' and tuple(sorted(r['support_pair'])) in wanted:
            details[tuple(sorted(r['support_pair']))] = r
    frequency = read(INPUT/'frequency_snapshot.json')
    freq = {r['entity_id']: r for r in frequency['entities']}
    def decompose(pair):
        r = details[tuple(sorted(pair))]; v = r['evidence']['evidence_v5']
        a, b = [alerts[i] for i in pair]
        gap = abs((datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')) -
                   datetime.fromisoformat(b['timestamp'].replace('Z', '+00:00'))).total_seconds())
        fs = v['features']
        groups = {}
        from app.correlation.formula_v5 import independent_groups
        for keys, ids, features in independent_groups(fs):
            groups['+'.join(sorted(keys))] = dict(entity_ids=sorted(ids),
                members=[dict(**f, weighted_support=f['strength']*f['reliability']) for f in features],
                group_max=max(f['strength']*f['reliability'] for f in features))
        byfamily = {name: [f for f in fs if f['family']==name] for name in ('entity','relation','time','behavior','source')}
        roles = [{**o, 'alert_id': a['alert_id']} for a in (a,b) for o in a['entity_occurrences']]
        shared = sorted(set(a['entity_ids']) & set(b['entity_ids']))
        return dict(canonical_alert_a=a, canonical_alert_b=b, time_gap_seconds=gap,
            entity_evidence=byfamily['entity'], relation_evidence=r['evidence']['relations'], role_evidence=roles,
            resource_evidence=[f for f in fs if f['name'] in ('entity.DOMAIN','entity.URL')],
            asset_evidence=[f for f in fs if f['name'] in ('entity.HOST','entity.IP')],
            execution_evidence=[f for f in fs if f['name'] in ('entity.PROCESS','entity.FILE','entity.COMMAND')],
            session_evidence=[f for f in fs if f['name']=='entity.SESSION'],
            network_evidence=[f for f in fs if f['name']=='topology.network_continuity'],
            direct_evidence=[f for f in fs if f['role']=='direct'], temporal_evidence=byfamily['time'],
            behavior_evidence=byfamily['behavior'], source_evidence=byfamily['source'], dependency_groups=groups,
            frequency=[dict(**freq[e], population=frequency['N']) for e in shared],
            entity_discounts=r['evidence']['evidence_v2']['entity_reliability'],
            evidence_mass=v['evidence_mass'], agreement=v['quality'], temporal_factor=v['temporal_factor'],
            conflict_penalty=v['conflict_penalty'], duplicate_penalty=v['duplicate_penalty'],
            weak_only=v['weak_only'], raw_total=v['raw_total'], final_score=r['score'],
            complete_frozen_evidence=r['evidence'])
    positives = {eid: decompose([r['source_alert_id'],r['target_alert_id']]) for eid,r in gt.items()}
    explanations = {
        'GT-E01': 'Only asset .039157 and resource .037752 survive quality/rarity/descriptor and fixed reliability; 191s (not 2s) temporal factor .928639. Scan/injection signatures remain canonical, both categories unknown; no scored behavior transition. IP-literal HTTP hostname duplicates destination identity across two groups.',
        'GT-E02': '251s gap; dst_ip-to-monitored-host identity is retained, but only .337173*.55=.185445 asset support. Web request and process/command exist, no request-to-process instance linkage. Unknown categories also disable network behavior context.',
        'GT-E03': 'Host and audit-account continuity accumulate .815149 mass. EXECVE and file-read operation are embedded in raw alert; file is not canonical. No shared process instance, parent PID/start or file-creator/executing-process link exists. Earlier execution and later file access are compatible but causality is unproved.',
        'GT-E04': 'Target account -> authenticated account plus monitored-host-IP -> login-source bridge are already extracted. Asset .185445 plus account .551036 mass .634295; 311s factor .897490. Current verifier ignores these roles unless a preattached AlertRelation exists.',
        'GT-E05': 'Host and authenticated-account -> audit-account continuity yield .805403 mass. Authentication success and sshd parent executable support a hypothesis, but no session ID, login PID or parent process instance binds this login to that shell. Parent executable alone is not lineage.',
        'GT-E06': '491s gap; host monitored IP -> network source retained at .433407*.55=.238374. Audit execution and later network alert are present, but no socket/process association proves that shell initiated the network request; network category unknown.'}
    for eid, value in positives.items(): value['interpretation']=explanations[eid]
    save(OUT/'gt_evidence_decomposition.json', positives)
    save(OUT/'hard_negative_decomposition.json', dict(explicit_definition='hard-alert x attack-alert, all 630 labelled not-related links',
        scored_count=len(negatives), pairs=[dict(support_pair=r['support_pair'], **decompose(r['support_pair']),
        interpretation='Context equality is real. No compatible grounded transition is scored; ceiling .45 caps single asset/account support. A negative label is never a scorer input.') for r in chosen],
        all_touching_caution='The .789637 pair is hard x hard, not an explicit attack x hard negative; recurring same operator, host and process descriptor can plausibly correlate without being attack progression.'))
    save(OUT/'positive_negative_contrast.json', dict(axes=['support strength','support quality','independence','rarity/frequency','role compatibility','event transition compatibility','temporal gap','entity role','source complementarity','behavior semantics'],
        positives={eid:dict(groups=v['dependency_groups'],gap=v['time_gap_seconds'],frequency=v['frequency'],roles=v['role_evidence'],interpretation=explanations[eid]) for eid,v in positives.items()},
        top_negative_pairs=[dict(pair=r['support_pair'],score=r['score']) for r in chosen],
        finding='Reliability is labelled as identity quality but operationally defines the whole continuity value. Concrete behavior transitions are absent from positive mass; single account/host equality can dominate sparse endpoint progression. Identity equality is not proof of an attack.'))
    save(OUT/'rarity_specificity_audit.json', dict(N=frequency['N'],frequency_unit=frequency['frequency_unit'],
        existing_formula='log((N+1)/(df+1))/log(N+1), then existing v3 quality/descriptor/role adjustments, then V5 reliability',
        findings=['Frequency is active; not a missing implementation.', 'High scoring explicit negatives reuse low-df planted assets/accounts, not 5000-occurrence globally hot identities.',
        'Entity-wise rarity cannot distinguish a rare benign operator from an attacker.', 'IP-literal domain alias is not independent resource evidence.', 'Do not implement another frequency-discount system.'],
        gt_entities={eid:v['frequency'] for eid,v in positives.items()},
        negative_entities=[dict(pair=r['support_pair'],entities=decompose(r['support_pair'])['frequency']) for r in chosen]))
    matrix=[]
    for eid,v in positives.items():
        a,b=v['canonical_alert_a'],v['canonical_alert_b']
        matrix.append(dict(edge=eid,src_alert=a['alert_id'],dst_alert=b['alert_id'],timestamp_order=a['timestamp']<b['timestamp'],
            src_dst_endpoint_roles=[o for o in v['role_evidence'] if o['role'] in ('src_ip','dst_ip','monitored_host_ip')],
            host_role=[a['host'],b['host']],account_role=[o for o in v['role_evidence'] if 'account' in o['role']],
            process_parent_child=[a['process'],a['parent_process'],b['process'],b['parent_process']],
            network_initiator_responder='Endpoint roles exist, response/receive/process ownership not attested',
            request_response='No cross-alert request/response identity',authentication_actor_target='Role fields available; see account and endpoint occurrences',
            resource_producer_consumer='No object producer/consumer link',file_process_creation='No creator/consumer instance',
            session_creation_use=[a['session'],b['session']],explicit_relation=v['relation_evidence'],flow_relation=v['network_evidence'],
            direction_evidence_available='Candidate access-pivot proof from two role channels' if eid=='GT-E04' else 'Context/behavior clues exist; causal or propagation relation unproved',
            direction_evidence_consumed=False,direction_rejection_reason='chain.explicit_propagation; both sides require preattached verified relation',
            field_level_conclusion=explanations[eid]))
    save(OUT/'direction_evidence_matrix.json',matrix)
    save(OUT/'transition_semantics_audit.json',dict(canonical_category_counts=dict(Counter(a['category'] for a in alerts.values())),
        source_field_losses=['audit.file and audit.operation remain raw only; structured detector semantics not normalized to categories',
        'audit.auid and data.target_user survive in semantic_observations; do not mistake canonical account=null for absent account evidence'],
        decision='One prospective candidate, no numeric optimization: bounded conditional behavior/role interaction, IP-literal alias dependency, access-pivot role verifier. Preserve missing/neutral states, existing rarity and hard guards. No category or dataset mutation.',
        allowed_direction='Account target -> authenticated account plus monitored source-host IP -> login source IP and different explicit execution hosts; no time-only edges.',
        observability_limit='E02/E03/E05/E06 lack unique cross-operation linkage. This does not prove the entire dataset is unobservable, because E04 has usable access direction.'))
    save(OUT/'audit_complete.json', dict(phases='A-G',production_code_changed=False,baseline_algorithm=frozen['algorithm_version'],
        gt_edges=len(positives),explicit_negative_decompositions=len(chosen),gt_seen_for_diagnosis=True,
        candidate_evaluation_is_development_not_unseen_validation=True,
        artifacts={p.name:sha(p) for p in OUT.glob('*.json') if p.name!='audit_complete.json'}))
    print('A_G_AUDIT_COMPLETE', flush=True)


if __name__=='__main__':run()

"""Post-seal alignment only. Never invokes a production candidate/scorer."""
import collections
import gzip
import itertools
import json
import re
from .runtime import ROOT, OUT, DATA, read, rows, save, sha, verify_frozen


def key(a,b): return tuple(sorted((a,b)))


def verify_seal():
    verify_frozen()
    access=read(OUT/'gt_access.json');manifest=read(OUT/'blind_manifest.json')
    if access['blind_manifest_sha256']!=sha(OUT/'blind_manifest.json'):
        raise ValueError('seal_identity_changed')
    if not all(sha(OUT/p)==h for p,h in manifest['files'].items()):
        raise ValueError('sealed_artifact_changed')
    return access


def binding_groups(truth):
    grouped=collections.defaultdict(list)
    for b in truth['observation_bindings']+[b for e in truth['edges'] for b in e['binding_evidence']]:
        k=(b['binding_type'],*key(b['source_alert_id'],b['target_alert_id']))
        if b not in grouped[k]: grouped[k].append(b)
    return grouped


def longest_path(edges, flag):
    distance=collections.defaultdict(int)
    for e in edges:
        if e[flag]: distance[e['target_stage']]=max(distance[e['target_stage']],distance[e['source_stage']]+1)
    return max(distance.values(),default=0)


class FrozenReplay:
    def __init__(self, variant, trace, wanted):
        self.variant=variant;self.directory=OUT/('blind_'+variant)
        self.alerts={a['alert_id']:a for a in rows(self.directory/'canonical.jsonl.gz')}
        byraw={(a['source_namespace'],a['raw_fingerprint']):aid for aid,a in self.alerts.items()}
        after={a['alert_id']:a for a in rows(OUT/'audit_canonical.jsonl.gz')}
        self.trace={eid:byraw.get((after[aid]['source_namespace'],after[aid]['raw_fingerprint'])) for eid,aid in trace.items()}
        self.owner=read(self.directory/'owner.json')
        self.candidates={tuple(p) for p in read(self.directory/'candidate_pairs.json')}
        self.admitted={}
        for edge in rows(self.directory/'admitted_edges.jsonl.gz'):
            self.admitted[key(edge['source_alert_id'],edge['target_alert_id'])]=edge
        needed=set()
        for a,b in wanted:
            aa,bb=self.trace.get(a),self.trace.get(b)
            if aa and bb: needed.add(key(aa,bb))
        self.scores={};self.nominations={};self.decisions={}
        wanted_groups={self.group_pair(a,b) for a,b in wanted}-{None}
        pair_pattern=re.compile(r'"support_pair":\["([^"]+)","([^"]+)"\]')
        group_pattern=re.compile(r'"support_key":\["([^"]+)","([^"]+)"\]')
        with gzip.open(self.directory/'diagnostics.jsonl.gz','rt',encoding='utf8') as f:
            for line in f:
                prefix=line[:1000]
                if prefix.startswith('{"stage":"member_score"'):
                    m=pair_pattern.search(prefix)
                    if m and key(*m.groups()) in needed:
                        row=json.loads(line);self.scores[key(*row['support_pair'])]=row
                elif prefix.startswith('{"stage":"candidate",'):
                    m=group_pattern.search(prefix)
                    if m and key(*m.groups()) in wanted_groups:
                        row=json.loads(line);self.nominations[key(*row['support_key'])]=row
                elif prefix.startswith('{"stage":"correlation_decision"'):
                    m=group_pattern.search(prefix)
                    if m and key(*m.groups()) in wanted_groups:
                        row=json.loads(line);self.decisions[key(*row['support_key'])]=row
        print('SEALED_DIAGNOSTICS_ALIGNED',variant,len(self.scores),flush=True)

    def group_pair(self,a,b):
        aa,bb=self.trace.get(a),self.trace.get(b)
        return key(self.owner[aa],self.owner[bb]) if aa and bb else None

    def pair(self,a,b):
        aa,bb=self.trace.get(a),self.trace.get(b);g=self.group_pair(a,b)
        score=self.scores.get(key(aa,bb)) if aa and bb else None
        formal=self.admitted.get(g)
        selected=key(*formal['support_pair'].values()) if formal else None
        return dict(source_alert_id=a,target_alert_id=b,canonical_alert_ids=[aa,bb],support_key=g,
            candidate=g in self.candidates if g else False,dedupe_collapsed=bool(g and g[0]==g[1]),
            score=score['score'] if score else None,valid=score['valid'] if score else None,
            admitted=bool(formal),exact_selected_witness=bool(formal and selected==key(aa,bb)),
            selected_support_pair=formal['support_pair'] if formal else None,
            candidate_channels=self.nominations.get(g,{}).get('channels',[]),
            decision=self.decisions.get(g),member_diagnostic=score)

    def binding(self,components):
        first=components[0];a,b=first['source_alert_id'],first['target_alert_id'];pair=self.pair(a,b)
        aa,bb=(self.alerts.get(x) for x in pair['canonical_alert_ids'])
        raw_present=True;projected=True;details=[]
        for c in components:
            item={**c,'sides':[]}
            for which in ('source','target'):
                eid=c[which+'_alert_id'];alert=self.alerts.get(self.trace.get(eid))
                path='/'+c[which+'_field'].removeprefix('event.').replace('.','/')
                value=alert['raw_alert'] if alert else None
                for part in path.strip('/').split('/'):
                    value=value.get(part) if isinstance(value,dict) else None
                present=value is not None and value==c['value']
                provenance=[k for k,v in alert['field_provenance'].items() if v['raw_pointer']==path] if alert else []
                occurrences=[o for o in alert['entity_occurrences'] if o['raw_pointer']==path] if alert else []
                raw_present &= present;projected &= bool(provenance or occurrences)
                item['sides'].append(dict(side=which,path=path,value=value,raw_matches=present,
                    canonical_fields=provenance,entity_occurrences=occurrences))
            details.append(item)
        shared=sorted(set(aa['entity_ids'])&set(bb['entity_ids'])) if aa and bb else []
        diag=pair['member_diagnostic'];used=diag['evidence'].get('shared_entity_ids',[]) if diag else []
        features=diag['evidence'].get('evidence_v5',{}).get('features',[]) if diag else []
        return dict(source_alert_id=a,target_alert_id=b,raw_observable=raw_present,
            canonical_projected=projected,recovered=raw_present and projected,
            represented_shared_entities=shared,relation_count=sum(len(x['relations']) for x in (aa,bb)) if aa and bb else 0,
            candidate_usable=pair['candidate'],score_used_entity_ids=used,
            score_used_features=[f for f in features if f['state']=='OBSERVED_SUPPORT'],
            scored=diag is not None,admitted=pair['admitted'],components=details)


def slim_pair(p):
    d=p['member_diagnostic'];result={k:v for k,v in p.items() if k!='member_diagnostic'}
    if d:
        v5=d['evidence']['evidence_v5']
        result.update(score_breakdown=dict(values=d['values'],contributions=d['contributions'],raw_total=d['raw_total'],
                v5={k:v for k,v in v5.items() if k!='features'}),
            features=v5['features'],evidence_families=sorted({f['family'] for f in v5['features'] if f['state']=='OBSERVED_SUPPORT'}),
            rejection_codes=d['rejection_codes'],evidence_refs=[r for f in v5['features'] for r in f.get('provenance',[])],
            shared_entity_ids=d['evidence'].get('shared_entity_ids',[]))
    return result


def main():
    verify_seal()
    truth=read(DATA/'ground_truth/ground_truth.json');hn=read(DATA/'hard_negative/ground_truth.json')
    if tuple(len(truth[k]) for k in ('stages','edges','observations'))!=(8,7,125):
        raise ValueError('DATASET_INTEGRITY_MISMATCH')
    trace_rows=read(OUT/'trace_map.json');trace={r['event_id']:r['alert_id'] for r in trace_rows}
    sources={r['event_id']:r['source'] for r in trace_rows}
    stages={s['stage_id']:s for s in truth['stages']};bindings=binding_groups(truth)
    totals=collections.Counter(k[0] for k in bindings)
    if totals!=dict(flow=15,request=2,process=2,auth_session=2,network_session=1):
        raise ValueError('DATASET_INTEGRITY_MISMATCH:bindings')
    negative_pairs={key(o['alert_id'],r) for o in hn['observations'] for r in o['related_alert_ids']}
    if len(negative_pairs)!=180 or len(hn['observations'])!=360: raise ValueError('DATASET_INTEGRITY_MISMATCH:HN')
    wanted=set(negative_pairs)|{key(k[1],k[2]) for k in bindings}
    for e in truth['edges']:
        wanted.update(key(a,b) for a,b in itertools.product(stages[e['source_stage']]['member_alert_ids'],stages[e['target_stage']]['member_alert_ids']))
    replay=FrozenReplay('A',trace,wanted);before=FrozenReplay('before',trace,wanted)
    edge_results=[]
    for e in truth['edges']:
        pp=sorted({key(c['source_alert_id'],c['target_alert_id']) for c in e['binding_evidence']})
        if len(pp)!=1: raise ValueError('ambiguous_authored_witness')
        a,b=pp[0];p=replay.pair(a,b);binding=replay.binding(e['binding_evidence'])
        d=p['member_diagnostic'];v5=d['evidence']['evidence_v5'] if d else None
        failure=('RAW_FIELD_MISSING' if not binding['raw_observable'] else 'PROJECTION_MISSING' if not binding['canonical_projected'] else
            'CANDIDATE_BLOCKED' if not p['candidate'] else 'PASS' if p['admitted'] else
            'SCORING_INSUFFICIENT' if v5 and (not v5['gate']['passed'] or v5['weak_only']) else 'ADMISSION_THRESHOLD')
        anypairs=[replay.pair(x,y) for x,y in itertools.product(stages[e['source_stage']]['member_alert_ids'],stages[e['target_stage']]['member_alert_ids'])]
        old=before.pair(a,b)
        edge_results.append(dict(edge_id=e['edge_id'],source_stage=e['source_stage'],target_stage=e['target_stage'],
            source_types=[sources[a],sources[b]],raw_evidence=e['binding_evidence'],projection=binding,
            **slim_pair(p),failure_stage=failure,
            before=dict(candidate=old['candidate'],score=old['score'],admitted=old['admitted']),
            stage_cartesian_upper_bound=dict(candidate=any(x['candidate'] for x in anypairs),admitted=any(x['admitted'] for x in anypairs),
                best_score=max((x['score'] for x in anypairs if x['score'] is not None),default=None)),
            direction='GT orientation used only for evaluation; production publishes undirected CorrelationEdge, not causal ChainEdge'))
    binding_results=[]
    for (kind,a,b),components in sorted(bindings.items()):
        row=replay.binding(components);row.update(binding_type=kind,cross_source=sources[a]!=sources[b],source_types=[sources[a],sources[b]])
        binding_results.append(row)
    counts={kind:dict(total=totals[kind],recovered=sum(r['recovered'] for r in binding_results if r['binding_type']==kind),
        candidate=sum(r['candidate_usable'] for r in binding_results if r['binding_type']==kind),
        scored=sum(r['scored'] for r in binding_results if r['binding_type']==kind),
        admitted=sum(r['admitted'] for r in binding_results if r['binding_type']==kind)) for kind in sorted(totals)}
    cross=[r for r in binding_results if r['cross_source']]
    if len(cross)!=20: raise ValueError('DATASET_INTEGRITY_MISMATCH:cross')
    counts['cross_source']=dict(total=20,recovered=sum(r['recovered'] for r in cross),candidate=sum(r['candidate_usable'] for r in cross),
        scored=sum(r['scored'] for r in cross),admitted=sum(r['admitted'] for r in cross))
    save('gt_binding_evaluation.json',dict(definition='Recovered = all authored native field/value components exist AND have canonical provenance/entity representation. This is not admission or a causal relation assertion.',
        counts=counts,bindings=binding_results))
    gt=dict(gt_stages=8,gt_edges=7,gt_observations=125,canonical_observations=sum(bool(replay.trace[o['alert_id']]) for o in truth['observations']),
        matching='Primary metrics use only each GT edge authored binding witness pair. Any stage Cartesian witness is a separately labeled upper bound.',
        candidate_count=sum(e['candidate'] for e in edge_results),admitted_count=sum(e['admitted'] for e in edge_results),
        candidate_recall=sum(e['candidate'] for e in edge_results)/7,admission_recall=sum(e['admitted'] for e in edge_results)/7,
        longest_recovered_progression=longest_path(edge_results,'admitted'),longest_gt_path_edges=7,
        progression_definition='Longest consecutive GT-stage path with admitted correlation witnesses; no directed ChainEdge reconstruction was executed or claimed.',
        stage_cartesian_candidate_count=sum(e['stage_cartesian_upper_bound']['candidate'] for e in edge_results),
        stage_cartesian_admitted_count=sum(e['stage_cartesian_upper_bound']['admitted'] for e in edge_results),
        edges=edge_results)
    save('gt_edge_evaluation.json',gt);save('gt_failure_breakdown.json',dict(counts=collections.Counter(e['failure_stage'] for e in edge_results),edges=edge_results))
    negatives=[];hnmap={o['alert_id']:o for o in hn['observations']}
    for a,b in sorted(negative_pairs):
        row=slim_pair(replay.pair(a,b));row.update(scenario_id=hnmap[a]['scenario_id'],negative_reason=hnmap[a]['negative_reason'],
            truth_scope=hnmap[a]['truth_scope']);negatives.append(row)
    admitted=sum(p['admitted'] for p in negatives);candidate=sum(p['candidate'] for p in negatives)
    scenario_counts={s:dict(total=sum(r['scenario_id']==s for r in negatives),candidate=sum(r['candidate'] for r in negatives if r['scenario_id']==s),
        admitted=sum(r['admitted'] for r in negatives if r['scenario_id']==s)) for s in sorted({r['scenario_id'] for r in negatives})}
    save('hard_negative_evaluation.json',dict(known_pairs=180,candidate=candidate,not_candidate=180-candidate,
        candidate_rejected=candidate-admitted,rejected=180-admitted,admitted=admitted,rejection_rate=(180-admitted)/180,
        progression_scope='Authored pairs deny attack progression; normal operational relations may exist. Admitted here means undirected correlation, not automatically a false causal ChainEdge.',
        scenarios=scenario_counts,pairs=negatives))
    attack={o['alert_id'] for o in truth['observations']};hnids=set(hnmap);background=set(trace)-attack-hnids
    if len(background)!=9500: raise ValueError('DATASET_INTEGRITY_MISMATCH:background')
    aid_to_eid={aid:eid for eid,aid in replay.trace.items() if aid}
    bgonly=touching=0
    for edge in replay.admitted.values():
        ids=[aid_to_eid[x] for x in edge['support_pair'].values()]
        bgonly+=all(x in background for x in ids);touching+=any(x in background for x in ids)
    save('unlabeled_background.json',dict(unlabeled_alerts=9500,unlabeled_background_admitted_edges=bgonly,
        background_touching_admitted_edges=touching,definition='Both selected support members are unlabeled background; touching also counts one background member. Neither is a false-positive or benign label.'))
    def identity_counts(rep):
        result=collections.Counter()
        for e in rows(rep.directory/'entities.jsonl.gz'):
            if e['type']=='PROCESS': result['process']+=1
            if e['type']=='SESSION':
                try: kind=json.loads(e['scope']).get('identity_kind','untyped')
                except (ValueError,TypeError): kind='untyped'
                result[kind]+=1
        return result
    save('before_after.json',dict(baseline_definition='Original supported Suricata native-body path (charitable manual envelope unwrap); other five native source shapes unsupported. Original as-is final wrapper entrypoint did not exist.',
        before={**read(before.directory/'receipt.json'), 'identity_counts':identity_counts(before),
            'GT_candidate_count':sum(e['before']['candidate'] for e in edge_results),'GT_admitted_count':sum(e['before']['admitted'] for e in edge_results)},
        after={**read(replay.directory/'receipt.json'),'identity_counts':identity_counts(replay),
            'GT_candidate_count':gt['candidate_count'],'GT_admitted_count':gt['admitted_count']}))
    print('GT_RESULT',json.dumps({k:v for k,v in gt.items() if k!='edges'}),flush=True)
    print('BINDINGS',counts,'HN',candidate,admitted,'BACKGROUND',bgonly,flush=True)


if __name__=='__main__': main()

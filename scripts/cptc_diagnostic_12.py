"""Read-only reachability audit. All reported pair scores use CorrelationScorer.

SQL computes conservative bounds ONLY to prune an all-pairs maximum search;
it never supplies a score, relation, admission decision or production object.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import replace
import json
import math
from pathlib import Path
import sqlite3
import sys
import tempfile

from cptc_top100_diagnostic import (
    ROOT, RUN, OUT as PREVIOUS, INPUT, frozen, saved_index, protected_hashes,
    read_json, atomic_json, records, CanonicalAlert, log,
)
from cptc_top100_report import score_features, validate_refs
from app.adapters.cptc import read_cptc_file, load_cptc_dataset
from app.adapters.suricata import SuricataAdapter
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.entities.extraction import extract_entities
from app.models.base import resolve_pointer
from app.services.storage import file_digest
from app.utils.stable_id import raw_fingerprint
from demo_support import truth_guard

OUT = ROOT / 'outputs/cptc_t5_correlation_v4_diagnostic_12'
FAMILIES = ('time', 'entity', 'relation', 'behavior', 'source')


def pair_result(pair, scorer):
    audit = pair.diagnostics['evidence_v2']
    return dict(score=pair.score, valid=pair.valid, formal_edge_eligible=pair.valid and pair.score >= .65,
        source_independence=pair.source_independence, values=pair.values,
        family_strengths=audit['family_strengths'], available_weight=audit['available_weight'],
        matched_weight=audit['matched_weight'], quality=audit['normalized_quality'], mass=audit['evidence_mass'],
        evidence_families=audit['evidence_families'], gate_reason=audit['gate_reason'],
        relations=[r.json_data() for r in pair.relations], rejection_codes=pair.rejection_codes,
        scoring=score_features(pair, scorer), dimensions=audit['dimensions'])


def native_fixtures(config, settings):
    """EVE -> actual Adapter -> Extraction -> actual scorer, no injected mapping."""
    base = next(iter(settings.values()))
    ingestion = load_cptc_dataset(ROOT).config
    rows = {}
    for sparse in (False, True):
        for cross in (False, True):
            aa, ss = [], {}
            for i in (0, 1):
                ns = 'diagnostic.synthetic.other' if cross and i else 'diagnostic.synthetic.suricata'
                setting = replace(base, source_namespace=ns)
                ss[ns] = setting
                raw = dict(event_type='alert', timestamp=f'2022-01-01T00:00:0{i}+0000',
                    src_ip='192.0.2.1', src_port=40000+i, proto='TCP', flow_id=100+i, tx_id=i,
                    alert=dict(signature_id=1000+i,signature='synthetic detector '+str(i),
                        category='Web Application Attack',severity=1),
                    http=dict(hostname='diagnostic.invalid', url='/specific/diagnostic-operation'))
                if not sparse:
                    raw.update(dest_ip='192.0.2.2', dest_port=80)
                aa.append(SuricataAdapter(ingestion, setting).convert(raw))
            ex = extract_entities(aa, ss)
            idx = AlertIndex(ex.alerts, (), ex.entities)
            scorer = CorrelationScorer(idx, config, ss)
            pair = scorer.score_pair(aa[0].alert_id, aa[1].alert_id)
            name = ('sparse' if sparse else 'complete_endpoints') + ('_cross' if cross else '_same')
            rows[name] = dict(**pair_result(pair,scorer),
                synthetic=True, adapter_roundtrip=True, source_type='suricata',
                source_namespaces=[a.source_namespace for a in aa],
                raw_alerts=[a.raw_alert for a in aa], config_hash=scorer.config_hash,
                mapped_categories=[a.category.value for a in aa],
                ingestion_mapping_digest=ingestion.mapping_digest)
    # A scorer-level conditional flow probe deliberately exposes the distinction
    # between canonical-model capabilities and this frozen native adapter recipe.
    sys.path.insert(0, str(ROOT/'backend/tests'))
    from test_correlation_score import alert, inputs, parent_child
    from test_correlation_v3 import network_event
    for cross in (False,True):
        aa = [network_event(alert('probe-a',source_type='suricata',namespace='one',
            category='initial_access', src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1000,dst_port=80),'flow-a'),
            network_event(alert('probe-b',1,source_type='suricata',namespace='two' if cross else 'one',
            category='lateral_movement',src_ip='192.0.2.2',dst_ip='192.0.2.3',src_port=1001,dst_port=80),'flow-b')]
        ss={a.source_namespace:replace(base,source_namespace=a.source_namespace) for a in aa}
        idx,ss=inputs(aa,ss)
        scorer=CorrelationScorer(idx,config,ss)
        pair=scorer.score_pair(aa[0].alert_id,aa[1].alert_id)
        rows['conditional_flow_'+('cross' if cross else 'same')]=dict(**pair_result(pair,scorer),
            synthetic=True, adapter_roundtrip=False,
            limitation='Canonical scorer probe only. Frozen Suricata mappings do not emit these categories. No attested directional relation is created.')
    # An actual namespace-only denominator change with unknown vendor categories:
    # no source bonus, but metadata becomes unavailable on the cross-source pair.
    for cross in (False,True):
        aa=[];ss={}
        for i in (0,1):
            ns='diagnostic.synthetic.other' if cross and i else 'diagnostic.synthetic.suricata'
            ss[ns]=replace(base,source_namespace=ns)
            raw=dict(event_type='alert',timestamp=f'2022-01-01T00:00:0{i}+0000',src_ip='192.0.2.1',
                proto='TCP',flow_id=100+i,alert=dict(signature_id=2000+i,signature='synthetic unknown '+str(i),
                category='synthetic unmapped category',severity=1),
                http=dict(hostname='diagnostic.invalid',url='/specific/diagnostic-operation'))
            aa.append(SuricataAdapter(ingestion,ss[ns]).convert(raw))
        ex=extract_entities(aa,ss);idx=AlertIndex(ex.alerts,(),ex.entities)
        scorer=CorrelationScorer(idx,config,ss)
        rows['unknown_metadata_'+('cross' if cross else 'same')]=dict(**pair_result(scorer.score_pair(aa[0].alert_id,aa[1].alert_id),scorer),
            synthetic=True,adapter_roundtrip=True,raw_alerts=[a.raw_alert for a in aa])
    aa=parent_child()
    idx,ss=inputs(aa)
    scorer=CorrelationScorer(idx,config,ss)
    rows['config_attested_witness']=dict(**pair_result(scorer.score_pair(aa[0].alert_id,aa[1].alert_id),scorer),
        synthetic=True, adapter_roundtrip=False, limitation='Generic canonical lineage fixture, not native Suricata data.')
    for prefix in ('sparse','complete_endpoints','conditional_flow','unknown_metadata'):
        a,b=rows[prefix+'_same'],rows[prefix+'_cross']
        rows[prefix+'_comparison']=dict(same_source_score=a['score'],cross_source_score=b['score'],
            difference=b['score']-a['score'], member_deltas={f:b['family_strengths'][f]-a['family_strengths'][f] for f in FAMILIES},
            source_namespace_only_changed=True,
            deployment_note='Other namespace is a synthetic declared source instance with identical network/asset/session scope. It is not proof of an actual second device or confirmed independence.')
    return rows


def scan_fields(top):
    raw_counts, canonical_counts, nested_keys, categories, vendors = Counter(), Counter(), Counter(), Counter(), Counter()
    fields={'timestamp':['/timestamp'],'src_ip':['/src_ip'],'dst_ip':['/dest_ip','/dst_ip'],
        'src_port':['/src_port'],'dst_port':['/dest_port','/dst_port'],'protocol':['/proto'],
        'host':['/host'],'account':['/account','/http/username'],'session':['/session'],
        'process':['/process'],'signature':['/alert/signature'],'rule_id':['/alert/signature_id'],
        'category':['/alert/category'],'behavior':['/behavior'],'relation':['/relations'],
        'source_namespace':['/source_namespace'],'network context':['/flow_id'],'url':['/http/url'],
        'domain':['/http/hostname','/tls/sni']}
    lookup={a['raw_fingerprint']:a for p in top for a in p['canonical_alerts'].values()}
    found=Counter()
    count=0
    for r in read_cptc_file(INPUT):
        assert r.error is None
        count+=1
        raw=r.eve
        for name,paths in fields.items():
            for ptr in paths:
                try: val=resolve_pointer(raw,ptr)
                except (ValueError,KeyError,IndexError,TypeError): continue
                if val is not None and val != '' and val != []:
                    raw_counts[name]+=1
                    break
        def walk(value,prefix=''):
            if isinstance(value,dict):
                for k,v in value.items():
                    nested_keys[prefix+'/'+k]+=1
                    walk(v,prefix+'/'+k)
        walk(raw)
        vendors[raw['alert'].get('category','')]+=1
        fp=raw_fingerprint(raw)
        if fp in lookup:
            assert raw==lookup[fp]['raw_alert']
            found[fp]+=1
    assert all(found[fp] for fp in lookup)
    for a in records('alerts',CanonicalAlert):
        categories[a.category.value]+=1
        for name in fields:
            value = a.raw_alert.get('proto') if name=='protocol' else a.raw_alert.get('flow_id') if name=='network context' else (
                a.relations if name=='relation' else a.category.value!='unknown' if name in ('behavior','category') else getattr(a,name,None))
            canonical_counts[name]+=value is not None and value is not False and value!='' and value!=[]
    return dict(raw_alert_count=count, fields=[dict(field=n,raw_available=raw_counts[n],
        raw_coverage=raw_counts[n]/count,canonical_available=canonical_counts[n],canonical_coverage=canonical_counts[n]/count,
        note='Read from preserved raw by scorer; no standalone CanonicalAlert protocol/flow_id field' if n in ('protocol','network context') else
             'Source namespace is deployment input, not expected as a native EVE field' if n=='source_namespace' else
             'Native vendor category vs mapped canonical category; behavior denotes mapped non-unknown category' if n in ('category','behavior') else '') for n in fields],
        all_raw_key_counts=dict(sorted(nested_keys.items())),canonical_category_counts=dict(categories),
        native_vendor_category_counts=dict(vendors),top_raw_roundtrip=dict(unique_fingerprints=len(found),records=sum(found.values()),status='PASS'))


def all_pair_bound_search(index,scorer,directory,observed):
    """Certify the finite-dataset maximum, including pairs never nominated.

    Bounds relax penalties and use a superset for relation-unavailable pairs.
    Every pair above the incumbent bound is evaluated by production scorer.
    """
    import duckdb
    assert scorer.algorithm.version=='v4'
    assert scorer.algorithm.score.weights.model_dump()==dict(time=.2,entity=.3,relation=.36,behavior=.04,source=.1,conflict=.45,duplicate=.4)
    assert not scorer.independence_mappings
    assert scorer.algorithm.score.evidence_v2.quality_factor==.65
    assert scorer.algorithm.score.evidence_v2.mass_factor==.35
    assert scorer.algorithm.score.evidence_v3.metadata_cap==.2
    with duckdb.connect(str(directory/'bounds.duckdb')) as db:
        db.execute("SET memory_limit='512MB'")
        db.execute('SET threads=1')
        db.execute('SET preserve_insertion_order=false')
        db.execute('CREATE TABLE a(n INT,id VARCHAR,t BIGINT,src VARCHAR,dst VARCHAR,sp INT,dp INT,dom VARCHAR,url VARCHAR,cat VARCHAR,rule VARCHAR,sig VARCHAR,rs DOUBLE,rd DOUBLE,ro DOUBLE,ru DOUBLE)')
        rows=[]
        metadata=[]
        for n,aid in enumerate(sorted(index.alerts)):
            a=index.alerts[aid]
            assert a.source_type.value=='suricata' and not a.relations
            assert a.category.value in ('unknown','web_attack') and a.src_ip and a.dst_ip and a.src_ip!=a.dst_ip
            assert a.rule_id and a.signature
            assert not any(getattr(a,f) for f in ('host','account','session','process','parent_process','file','command'))
            byrole={o.role.value:o.entity_id for o in a.entity_occurrences}
            assert {index.entities[e].type.value for e in a.entity_ids}<={'IP','DOMAIN','URL'}
            def eid(role): return byrole.get(role)
            def reliability(role):
                e=eid(role)
                return .1+.9*scorer.evidence_evaluator.rarity(e) if e else 0.
            # URL specificity: dataset URL scope has a host/domain or absolute URL;
            # relaxing descriptor factors to 1 can only increase this bound.
            rows.append((n,aid,index.times[aid],eid('src_ip'),eid('dst_ip'),a.src_port,a.dst_port,
                eid('domain'),eid('url'),a.category.value,a.rule_id,a.signature,
                reliability('src_ip'),reliability('dst_ip'),reliability('domain'),reliability('url')))
            metadata.append((n,aid,a.category.value,a.rule_id,a.signature,bool(a.url),bool(a.domain)))
            if (n+1)%10000==0:
                log('bound_input_prepared',alerts=n+1)
        staged=directory/'bound_input.jsonl'
        columns=('n','id','t','src','dst','sp','dp','dom','url','cat','rule','sig','rs','rd','ro','ru')
        with staged.open('w',encoding='utf8') as handle:
            for row in rows:
                handle.write(json.dumps(dict(zip(columns,row)),ensure_ascii=False)+'\n')
        db.execute('COPY a FROM ? (FORMAT JSON)',[str(staged)])
        rows.clear()
        staged.unlink()
        # At AW=.9, even E=1,B=.2 cannot exceed the incumbent after this delta.
        scale=.65/.9+.35
        need=(observed/scale-.3-.04*.2)/.2
        cutoff=-300*math.log2(need)
        joins=[]
        for x,y in [('src','src'),('dst','dst'),('src','dst'),('dst','src'),('dom','dom'),('url','url')]:
            joins.append(f'a.{x}=b.{y} AND a.n<b.n AND abs(a.t-b.t)<={cutoff*1_000_000+1}')
        # Only these extra pairs could have relation AW removed by the v4 unknown
        # category branch after v3 port-context validation. Include a superset.
        for condition in ['a.t<b.t AND a.dst=b.src AND a.dp=b.sp','b.t<a.t AND b.dst=a.src AND b.dp=a.sp']:
            joins.append('a.n<b.n AND ('+condition+") AND (a.cat='unknown' OR b.cat='unknown')")
        db.execute('CREATE TABLE qualified(aid VARCHAR,bid VARCHAR,ub DOUBLE)')
        # E is bounded using production rarity and all possible shared role pairs.
        query='''WITH e AS (SELECT a.id aid,b.id bid,
          greatest(CASE WHEN a.src=b.src THEN a.rs ELSE 0 END,
                   CASE WHEN a.dst=b.dst THEN .25*a.rd ELSE 0 END,
                   CASE WHEN a.src=b.dst THEN .8*a.rs ELSE 0 END,
                   CASE WHEN a.dst=b.src THEN .8*a.rd ELSE 0 END) ip,
          CASE WHEN a.dom=b.dom THEN a.ro ELSE 0 END dom,
          CASE WHEN a.url=b.url THEN a.ru ELSE 0 END url,
          .25+CASE WHEN a.dom IS NOT NULL AND b.dom IS NOT NULL THEN .35 ELSE 0 END
              +CASE WHEN a.url IS NOT NULL AND b.url IS NOT NULL THEN .85 ELSE 0 END den,
          CASE WHEN a.rule=b.rule OR a.sig=b.sig THEN .2
               WHEN a.cat='web_attack' AND b.cat='web_attack' THEN .08 ELSE 0 END meta,
          exp(-ln(2)*(abs(a.t-b.t)/1000000)/300) tv,
          CASE WHEN (a.cat='unknown' OR b.cat='unknown') AND
             ((a.t<b.t AND a.dst=b.src AND a.dp=b.sp) OR (b.t<a.t AND b.dst=a.src AND b.dp=a.sp)) THEN .54 ELSE .9 END aw
          FROM a JOIN a b ON JOIN_CONDITION),
          u AS (SELECT *, (.65/aw+.35)*(.2*tv+.3*(.25*ip+.35*dom+.85*url)/den+.04*meta)+1e-12 ub FROM e)
          SELECT aid,bid,ub FROM u WHERE ub>=? ORDER BY ub DESC,aid,bid'''
        for part,condition in enumerate(joins,1):
            db.execute('INSERT INTO qualified '+query.replace('JOIN_CONDITION',condition),[observed-1e-12])
            log('bound_join_complete',part=part,parts=len(joins),qualified_rows=db.execute('SELECT count(*) FROM qualified').fetchone()[0])
        surviving=db.execute('SELECT count(*) FROM (SELECT DISTINCT aid,bid FROM qualified)').fetchone()[0]
        cursor=db.execute('SELECT aid,bid,max(ub) ub FROM qualified GROUP BY aid,bid ORDER BY ub DESC,aid,bid')
        checked=0
        maximum=observed
        best=None
        highest_remaining=None
        for aid,bid,ub in cursor.fetchall():
            if ub < maximum-1e-12:
                highest_remaining=ub
                break
            p=scorer.score_pair(aid,bid)
            assert p.score<=ub+1e-12,('non_conservative_bound',p.score,ub,aid,bid)
            checked+=1
            if p.score>maximum or best is None and p.score==maximum:
                maximum=p.score
                best=dict(alert_a=aid,alert_b=bid,**pair_result(p,scorer))
        result=dict(DATASET_REACHABLE_MAX=maximum,kind='exact_numeric_maximum_over_all_distinct_real_alert_pairs',
            includes_pairs_outside_candidate_admission=True,includes_invalid_or_same_dedupe_group_pairs=True,
            checked_by_production_scorer=checked,all_pair_count=index.alert_count*(index.alert_count-1)//2 if hasattr(index,'alert_count') else len(index.alerts)*(len(index.alerts)-1)//2,
            bound_threshold_survivor_count=surviving,
            normal_availability_ceiling=(.2+.3+.04*.2)*scale,
            temporal_pruning_seconds=cutoff,highest_remaining_upper_bound=highest_remaining,witness=best,
            proof='No raw/canonical relations or process instances; only unknown/web_attack categories, so network strength=0 and source=0. All records have distinct complete endpoints. Normal AW=.9; exceptional AW=.54 is over-included by chronological endpoint+port bridge with unknown category. Pairs without any shared entity cannot beat the observed incumbent. Normal pairs outside cutoff cannot beat it even with E=1 and metadata=.2. SQL ranks conservative bounds for the remaining real pairs; actual scorer evaluates every bound above incumbent. Descriptor weakening, conflicts, duplicates and event-flow validation only lower bounds. No SQL score is reported as a scorer result.')
        return result,metadata


def population_coverage(metadata,top):
    db=sqlite3.connect('file:'+str(PREVIOUS/'compact_scores.sqlite').replace('\\','/')+'?mode=ro',uri=True)
    db.execute('CREATE TEMP TABLE meta(n INT,id TEXT,cat TEXT,rule TEXT,sig TEXT,url INT,dom INT)')
    db.executemany('INSERT INTO meta VALUES (?,?,?,?,?,?,?)',metadata)
    # Numeric indices in the old compact store are sorted IDs; verify, don't assume.
    assert db.execute('SELECT count(*) FROM alerts a JOIN meta m ON a.i=m.n WHERE a.id!=m.id').fetchone()[0]==0
    count=db.execute('SELECT count(*) FROM members').fetchone()[0]
    meta_nonzero=db.execute("SELECT count(*) FROM members p JOIN meta a ON p.a=a.n JOIN meta b ON p.b=b.n WHERE a.rule=b.rule OR a.sig=b.sig OR (a.cat='web_attack' AND b.cat='web_attack')").fetchone()[0]
    stats=[]
    for table in ('members','candidates'):
        row=db.execute('SELECT count(*),max(score),sum(score>=.60),sum(score>=.62),sum(score>=.64),sum(score>=.65) FROM '+table).fetchone()
        stats.append(dict(population=table,**dict(zip(('count','observed_max','ge_060','ge_062','ge_064','ge_065'),row))))
    db.close()
    old=read_json(PREVIOUS/'CPTC_TOP100_SCORE_DISTRIBUTION.json')
    family=[]
    for f in FAMILIES:
        aud=[p['production_diagnostic']['evidence_v2'] for p in top]
        avail=sum(any(d['family']==f and d['state'].startswith('AVAILABLE') for d in a['dimensions']) for a in aud)
        nonzero=sum(a['family_strengths'][f]>0 for a in aud)
        family.append(dict(family=f,population='Top100 actual scored members',denominator=100,
            available_pair_count=avail,available_pair_ratio=avail/100,nonzero_pair_count=nonzero,nonzero_pair_ratio=nonzero/100,
            max_observed_contribution=max(next(x['positive_contribution'] for x in p['scoring']['family_contributions'] if x['feature_name']=='family.'+f) for p in top)))
    return dict(populations=stats,same_source_candidate_count=stats[1]['count'],same_source_scored_count=count,
        same_source_p95=old['p95'],same_source_p99=old['p99'],all_scored_family_nonzero_counts=dict(time=count,
            behavior=meta_nonzero,relation=0,source=0,entity=None),
        caveat='All-score entity strengths were not retained. Exact entity nonzero count is unavailable without replaying all 1.7M comparisons; Top100 states below are exact. Relation availability varies; nonzero is provably zero from category/lineage audit. No sample ratio is represented as a full-population ratio.',
        top100_family_coverage=family)


def enrich_population_coverage(population):
    """Exact full-population availability/nonzero counts from immutable fields.

    Numeric strengths are not replayed. Under the audited t5 invariant,
    relation/source strengths are always zero and entity nonzero is equivalent
    to sharing any scoped extracted entity (none can be consumed by topology).
    """
    db=sqlite3.connect('file:'+str(PREVIOUS/'compact_scores.sqlite').replace('\\','/')+'?mode=ro',uri=True)
    db.execute('CREATE TEMP TABLE facts(n INT PRIMARY KEY,id TEXT,t TEXT,s TEXT,d TEXT,sp INT,dp INT,dom TEXT,url TEXT,cat TEXT,rule TEXT,sig TEXT,flow INT,proto TEXT)')
    rows=[]
    for n,a in enumerate(records('alerts',CanonicalAlert)):
        roles={o.role.value:o.entity_id for o in a.entity_occurrences}
        rows.append((n,a.alert_id,a.timestamp,roles.get('src_ip'),roles.get('dst_ip'),a.src_port,a.dst_port,
            roles.get('domain'),roles.get('url'),a.category.value,a.rule_id,a.signature,
            int(a.raw_alert.get('flow_id') is not None),str(a.raw_alert.get('proto','')).upper()))
    db.executemany('INSERT INTO facts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',rows)
    assert db.execute('SELECT count(*) FROM alerts a JOIN facts f ON a.i=f.n WHERE a.id!=f.id').fetchone()[0]==0
    condition="""a.t!=b.t AND (a.cat='unknown' OR b.cat='unknown') AND a.flow AND b.flow
        AND a.proto!='' AND a.proto=b.proto AND a.sp IS NOT NULL AND b.sp IS NOT NULL
        AND a.dp IS NOT NULL AND b.dp IS NOT NULL AND
        ((a.t<b.t AND a.d=b.s AND a.dp=b.sp) OR (b.t<a.t AND b.d=a.s AND b.dp=a.sp))"""
    out=[]
    for table in ('members','candidates'):
        n,entity,meta,unavailable=db.execute('''SELECT count(*),
          sum(a.s=b.s OR a.d=b.d OR a.s=b.d OR a.d=b.s OR coalesce(a.dom=b.dom,0) OR coalesce(a.url=b.url,0)),
          sum(a.rule=b.rule OR a.sig=b.sig OR (a.cat='web_attack' AND b.cat='web_attack')),
          sum('''+condition+''') FROM '''+table+' p JOIN facts a ON a.n=p.a JOIN facts b ON b.n=p.b').fetchone()
        for family,avail,nonzero in [('time',n,n),('entity',n,entity),('relation',n-unavailable,0),('behavior',n,meta),('source',0,0)]:
            out.append(dict(population=table,family=family,denominator=n,available_pair_count=avail,
                available_pair_ratio=avail/n,nonzero_pair_count=nonzero,nonzero_pair_ratio=nonzero/n,
                method='Exact field/identity predicate under independently asserted t5 invariants; final scores remain production scorer values.'))
    db.close()
    population['all_scored_family_coverage']=out
    population['all_scored_family_nonzero_counts']={r['family']:r['nonzero_pair_count'] for r in out if r['population']=='members'}
    population['caveat']='All-population availability/nonzero counts are exact field predicates under the audited t5 invariants, not a Top100 extrapolation. Magnitudes/final contributions below are from 100 freshly rescored pairs only; no unretained all-population contribution distribution is invented.'
    return population


def top_breakdowns(top,index,scorer):
    result=[]
    for row in top:
        a,b=row['alert_a_id'],row['alert_b_id']
        pair=scorer.score_pair(a,b)
        assert pair.score==row['final_score']
        audit=pair.diagnostics['evidence_v2']
        features=score_features(pair,scorer)
        assert features['status']=='PASS'
        cf={f['feature_name'].removeprefix('family.'):f['net_contribution'] for f in features['family_contributions']}
        # Hypothetical arithmetic ceilings are sensitivity bounds, NOT fabricated
        # evidence fed to the scorer and never treated as actual recovered signals.
        counterfactual=[]
        for fam in FAMILIES:
            if fam=='time': continue
            w=audit['family_weights'][fam]
            available=any(d['family']==fam and d['state'].startswith('AVAILABLE') for d in audit['dimensions'])
            strength_cap=.2 if fam=='behavior' else 1.
            mw=audit['matched_weight']+w*(strength_cap-audit['family_strengths'][fam])
            aw=audit['available_weight']+(0 if available else w)
            upper=min(1.,.65*mw/aw+.35*mw-features['penalty_total'])
            counterfactual.append(dict(family=fam,optimistic_score_ceiling=upper,could_cross_arithmetically=upper>=.65,
                recoverable_from_this_raw=False,
                reason='No positive source independence mapping in frozen recipe' if fam=='source' else
                    'No attested propagation; same-directed endpoints are not dst-to-src flow. Cannot add relation from these alerts' if fam=='relation' else
                    'Observed entity identities/frequency and metadata already used; cap requires different evidence, not a known lost field'))
        result.append(dict(rank=row['rank'],alert_a=a,alert_b=b,time_delta=pair.diagnostics['gap_seconds'],
            source_a=index.alerts[a].source_namespace,source_b=index.alerts[b].source_namespace,same_source=True,
            shared_entities=row['shared_entity_role_matching']['shared_entities'],
            directional_entities=row['network_continuity'],
            **{f+'_score':audit['family_strengths'][f] for f in FAMILIES},
            final_family_contributions=cf,penalties={k:pair.contributions[k] for k in ('conflict','duplicate')},
            final_score=pair.score,missing_score_members=audit['unavailable_evidence']+audit['not_applicable_evidence'],
            measured_mismatches=audit['mismatched_evidence'],threshold_gap=.65-pair.score,distance_to_threshold=.65-pair.score,
            one_family_sensitivity=counterfactual,recoverable_single_family_crossing=False,
            evidence_gate_passed=audit['evidence_gate_passed'],gate_reason=audit['gate_reason'],
            complete_score_breakdown=features,raw_pointer_validation=validate_refs(pair,{a:index.alerts[a],b:index.alerts[b]})))
    return result


def drilldowns(top):
    # Evidence-only proxy, not attack labels: directed endpoint overlap, distinct
    # signatures, independently identified observations, then shortest time gap.
    ranked=sorted(top,key=lambda p:(not(p['network_continuity']['same_directed_ip_pair'] and not p['signature_semantics']['same_signature']),
        p['evidence_independence']['duplicate_risk'],p['temporal']['absolute_time_delta_seconds'],p['rank']))[:10]
    return [dict(rank=p['rank'],alert_a=p['alert_a_id'],alert_b=p['alert_b_id'],
        selection_basis='Observed same directed communication endpoints + different signatures + distinct observation identities; time proximity tie-break. This is an investigation proxy, not proof of a common attack.',
        why_candidate=p['candidate_admission'],shared_evidence=p['shared_entity_role_matching'],
        continuity=p['network_continuity'],signatures=p['signature_semantics'],score=p['final_score'],
        threshold_gap=.65-p['final_score'],raw_alerts=p['raw_alerts'],canonical_provenance={k:a['field_provenance'] for k,a in p['canonical_alerts'].items()},
        missing_evidence=[dict(family='host/account/session/process/lineage',classification='A',
            reason='Absent as structured native EVE facts. HTTP hostname is network/HTTP target context, not an asset HOST attestation; flow_id/tx_id are observation context, not scoped session operation order.'),
            dict(family='attested_relation',classification='A',reason='No explicit propagation or request-to-process linkage. Shared endpoint/URL/time does not attest a directed operation.'),
            dict(family='network_continuity',classification='F',reason='Raw same-src/same-dst continuity exists, but frozen scorer uses chronological dst-to-src bridge plus flow and behavior context. Existing same-direction evidence contributes only via entity dimensions; this is a policy restriction, not an extraction loss.'),
            dict(family='source',classification='A',reason='One declared IDS instance; no independence evidence; no independent-source mappings.'),
            dict(family='payload/protocol/flow_id',classification='F',reason='Protocol/flow_id are used directly from raw for observation identity and topology validation. Payload text is not independently interpreted as new facts; identical encoded payload in a URL is not a process/command-execution fact.')],
        adapter_loss_confirmed=False,canonical_loss_confirmed=False,entity_loss_confirmed=False,
        relation_mapping_loss_confirmed=False,raw_to_frozen_score_explanation='Extracted IP/DOMAIN/URL are used with rarity and destination role discount. Detector metadata is capped/merged. Available network topology has strength zero; source unavailable; quality+mass total stays below threshold. No missing real family from these raw pairs can simply be recovered to cross .65.') for p in ranked]


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    before=protected_hashes()
    previous_files={p.name:file_digest(p) for p in PREVIOUS.iterdir() if p.is_file()}
    config,settings,recipe=frozen()
    old_manifest=read_json(PREVIOUS/'CPTC_TOP100_MANIFEST.json')
    for name,digest in old_manifest['files'].items():
        assert file_digest(PREVIOUS/name)==digest,'previous_artifact_changed:'+name
    top=[json.loads(line) for line in (PREVIOUS/'CPTC_TOP100_PAIRS.jsonl').read_text(encoding='utf8').splitlines()]
    assert len(top)==100
    log('frozen_verified',algorithm_version=recipe['algorithm_version'])
    with truth_guard(ROOT):
        fixtures=native_fixtures(config,settings)
        atomic_json(OUT/'single_vs_cross_source.json',fixtures)
        if '--refresh' in sys.argv:
            prior=read_json(OUT/'frozen_recipe_receipt.json')
            assert prior['protected_file_hashes']==before
            coverage=read_json(OUT/'score_member_coverage.json')
            population=enrich_population_coverage(coverage.copy())
            decomposed=read_json(OUT/'top100_score_breakdown.json')
            maximum=read_json(OUT/'score_reachability.json')['dataset_max_certificate']
            log('reuse_certified_maximum',maximum=maximum['DATASET_REACHABLE_MAX'])
        else:
            coverage=scan_fields(top)
            log('raw_coverage_complete',count=coverage['raw_alert_count'])
            with tempfile.TemporaryDirectory(prefix='diagnostic_tmp_',dir=OUT) as tmp:
                directory=Path(tmp)
                with saved_index(config,settings,directory/'index') as (index,scorer):
                    decomposed=top_breakdowns(top,index,scorer)
                    log('top100_rescored',count=len(decomposed))
                    maximum,metadata=all_pair_bound_search(index,scorer,directory,old_manifest['max_score'])
            population=enrich_population_coverage(population_coverage(metadata,top))
    atomic_json(OUT/'score_member_coverage.json',coverage | population)
    atomic_json(OUT/'top100_score_breakdown.json',decomposed)
    atomic_json(OUT/'pair_drilldown.json',drilldowns(top))
    theoretical=.65+.35*(.2+.3+.36)
    reach=dict(CONFIG_THEORETICAL_MAX=theoretical,
        config_max_kind='supremum under frozen recipe (source unavailable; metadata legitimately unavailable; time/entity/relation strengths approach 1). A=.86, M approaches .86, so .65+.35*.86=.951. Entity reliability approaches 1 with growing population; not a finite attained maximum.',
        all_applicable_metadata_present_supremum=(.2+.3+.36+.04*.2)*(.65/.9+.35),
        nominal_all_families_relaxed_ceiling=.2+.3+.36+.04*.2+.1,
        nominal_ceiling_is_reachable_under_frozen_mapping=False,
        DATASET_REACHABLE_MAX=maximum['DATASET_REACHABLE_MAX'],dataset_max_certificate=maximum,
        OBSERVED_MAX=old_manifest['max_score'],formal_threshold=.65,reachable=maximum['DATASET_REACHABLE_MAX']>=.65,
        same_source_score_supremum=theoretical,cross_source_score_supremum=theoretical,
        paired_native_single_source_fixture_score=fixtures['sparse_same']['score'],
        paired_native_cross_source_fixture_score=fixtures['sparse_cross']['score'],
        best_native_single_source_fixture_score=max(v['score'] for k,v in fixtures.items() if k.endswith('_same') and v.get('adapter_roundtrip')),
        best_native_cross_source_fixture_score=max(v['score'] for k,v in fixtures.items() if k.endswith('_cross') and v.get('adapter_roundtrip')),
        best_native_fixture_is_global_optimum=False,
        BEST_LEGAL_SINGLE_SOURCE_SCORE=None,
        BEST_LEGAL_CROSS_SOURCE_SCORE=None,
        requested_best_pair_status='INFEASIBLE under joint native Suricata + frozen mapping + attested directed relation constraints; sparse undirected witnesses and proven suprema are reported separately, not mislabeled as a best directed pair.',
        native_suricata_same_source_supremum=.65+.35*.5,
        native_suricata_cross_source_supremum=.65+.35*.5,
        complete_same_direction_endpoint_ceiling=maximum['normal_availability_ceiling'],
        alert_type_score_ceiling_profiles=[
            dict(profile='complete_same_direction_network_same_source',ceiling=maximum['normal_availability_ceiling'],
                kind='relaxed upper bound',conditions='Ideal T/E, metadata<=.2, topology observable but zero, source unavailable; gates still required'),
            dict(profile='sparse_native_network_metadata_available',ceiling=(.2+.3+.04*.2)*(.65/.54+.35),
                kind='supremum',conditions='No evaluable topology, ideal T/E, metadata=.2, no penalties; not t5'),
            dict(profile='sparse_native_network_metadata_unavailable',ceiling=.65+.35*.5,
                kind='supremum',conditions='No evaluable topology, ideal T/E, metadata/source unavailable; primary required; not t5'),
            dict(profile='generic_attested_lineage_metadata_available',ceiling=(.2+.3+.36+.04*.2)*(.65/.9+.35),
                kind='supremum',conditions='Ideal T/E/R, metadata=.2, source unavailable; not native t5'),
            dict(profile='generic_attested_lineage_metadata_unavailable',ceiling=theoretical,
                kind='supremum',conditions='Ideal T/E/R, metadata/source legitimately unavailable; not native t5')],
        exact_best_native_pair_with_attested_direction=None,
        attested_direction_limitation='Requested best native Suricata pair with valid directed relation cannot be constructed from frozen native Adapter/Extraction: no host/process/session linkage or raw network-pivot attestation extraction. Conditional canonical flow provides undirected topology only. Do not fabricate a causal relation.',
        root_cause=dict(result='MIXED_CAUSE',primary=['A Dataset evidence limitation','D Score reachability design for complete same-direction endpoint observations'],
            secondary=['C Category mapping coverage limits behavior transitions; no demonstrated recoverable raw propagation field',
                'E Conditional namespace/metadata availability bias demonstrated on unknown-category fixtures, not a cross-source hard dependency'],
            not_established=['B Recoverable Adapter/entity extraction loss in Top100','E Cross-source requirement','F Candidate omission as explanation for zero edges']),
        questions=dict(Q1='YES' if maximum['DATASET_REACHABLE_MAX']>=.65 else 'NO',
            Q2='YES for fixed mass denominator and available-zero families; quality does renormalize unavailable families, so not a blanket fixed-point permanent-loss rule.',
            Q3='NO',Q4='CONDITIONAL: YES for native sparse same-source undirected correlation; NO for complete same-directed endpoints under frozen native mapping, and no attested native directional relation can be fabricated.',
            Q5=dict(same=fixtures['sparse_same']['score'],cross=fixtures['sparse_cross']['score'],delta=fixtures['sparse_comparison']['difference'],
                unknown_category_namespace_effect=fixtures['unknown_metadata_comparison']),Q6='G Mixed: A+D primary; C secondary. Conditional namespace-availability bias exists, but no demonstrated extraction loss or source-name-only independence bonus.'))
    atomic_json(OUT/'score_reachability.json',reach)
    assert protected_hashes()==before,'protected_files_changed'
    assert {p.name:file_digest(p) for p in PREVIOUS.iterdir() if p.is_file()}==previous_files
    receipt=dict(**recipe,algorithm_modified=False,config_modified=False,mapping_modified=False,threshold_modified=False,
        ground_truth_read=False,protected_file_hashes=before,previous_diagnostic_hashes=previous_files,
        frozen_verification='PASS',production_snapshot_modified=False,
        ingestion_config_snapshot=load_cptc_dataset(ROOT).config.snapshot,
        ingestion_mapping_digest=load_cptc_dataset(ROOT).config.mapping_digest,
        diagnostic_code_sha256=file_digest(Path(__file__)),
        diagnostic_test_sha256=file_digest(ROOT/'backend/tests/test_cptc_diagnostic_12.py'),
        score_rules=config.snapshot['score'],time_windows=config.snapshot['time'],candidate_rules=config.snapshot['candidate'],
        source_scoring_rule=config.snapshot['source'],relation_mapping=config.snapshot['chain'],guard_rules=config.snapshot['conflict'])
    atomic_json(OUT/'frozen_recipe_receipt.json',receipt)
    write_report(reach,coverage,population,fixtures,decomposed,config)
    log('DIAGNOSTIC_12_RESULT',result='MIXED_CAUSE',dataset_reachable_max=maximum['DATASET_REACHABLE_MAX'],native_same=fixtures['sparse_same']['score'])


def write_report(r,c,p,f,top,config):
    recipe=read_json(RUN/'recipe.json')
    lines=['# Correlation v4 — Diagnostic 1+2',
        '仅诊断；未读取 Ground Truth，未启动诊断 3/4 或算法修复。所有真实 pair 与受控 fixture 的最终分数均调用正式 CorrelationScorer。',
        '## 冻结版本',
        f"algorithm_version=`{recipe['algorithm_version']}`；config_hash=`{recipe['config_hash']}`；mapping_digest=`{recipe['mapping_digest']}`；threshold=.65。",
        '版本、运行 config_hash、mapping_digest、完整 score/time/candidate/source/relation/guard 快照及修改前后文件摘要见 frozen_recipe_receipt.json。config_hash 是生产算法+部署来源快照摘要，与仅算法 config hash 不混用。',
        'algorithm modified = NO\n\nconfig modified = NO\n\nmapping modified = NO\n\nthreshold modified = NO',
        '## 正式公式与证据要求',
        '`S=clamp(.65*M/A + .35*M/W - .45*C - .4*D,0,1)`；`W=1`；`A=Σ可用家族权重`；`M=Σ可用家族权重×强度`。',
        '| score member | 家族权重 | 触发/证据 | 缺失/不匹配行为 |',
        '|---|---:|---|---|',
        '| time.distance | .20 | timestamp；指数半衰期，默认300秒，转换例外见 receipt | 缺时间在 Adapter 隔离；非缺失值持续衰减 |',
        '| entity.IP/HOST/ACCOUNT/SESSION/PROCESS/URL/DOMAIN/FILE/COMMAND | .30 | scoped 共享实体；类型内取最高可靠性，类型间按 entity.weights 加权均值 | 双方缺失NOT_APPLICABLE/单侧缺失UNAVAILABLE，移除类型分母；双方具备但不同为AVAILABLE_MISMATCH |',
        '| topology.attested_relation / topology.network_continuity | .36 | 已核验关系或有序 dst→src+独立flow+兼容行为；家族取max | 无attestation不可伪造；完整端点但无桥为AVAILABLE_MISMATCH，保留零分分母；部分不可评估分支为UNAVAILABLE |',
        '| metadata.detector_identity | .04 | 同源rule/signature或已知category兼容；多个字段合并一次，最高×.2 | 类型alert不供应primary；跨namespace不比较vendor rule/signature；无可用字段时UNAVAILABLE |',
        '| context.independent_complement | .10 | confirmed_independent+不同侧面+host/session/关系桥；同sensor为0 | unknown=UNAVAILABLE，same_origin=NOT_APPLICABLE；冻结独立性映射为空，因此本recipe所有来源名称组合均无source奖励 |',
        '| conflict | -.45 | hard/soft规则见receipt，soft取最大强度 | 缺字段不作为冲突；hard不能由高分抵消 |',
        '| duplicate | -.40 | 正式重复观察/疑似重复评分 | dup<.5无罚，以上线性变换；重复观察另有gate保护 |',
        '家族实际贡献不是固定 weight×strength，而是 `weight×strength×(.65/A+.35/W)`。旧七项 raw_values/contributions 仅审计，不能相加当v4最终分。Entity reliability=`(.1+.9*rarity)*role*descriptor`；rarity=`max(.1,ln((max(N,100)+1)/(df+1))/ln(max(N,100)+1))`，频率单位dedupe group；dst-only IP再乘.25，普通src↔dst乘.8，弱资源descriptor乘.25。已用于topology/关系的实体会去重，不在entity重复计分。',
        'Gate：存在可靠primary、不是同一观察、mass≥.25；HOST/ACCOUNT还需不同detector或已知行为不同；PROCESS需实例、SESSION需scope/rarity、URL等需具体且稀有。IP/DOMAIN/metadata/time本身不能单独作primary。正式无向CorrelationEdge还需non-time支持、无hard guard、score≥.65。ChainEdge另需真实显式关系、.70支撑及方向guard；两者不可混淆。',
        '## 三种最高分',
        f"CONFIG_THEORETICAL_MAX = {r['CONFIG_THEORETICAL_MAX']:.12f}（冻结recipe的上确界，非有限样本必然达到）；DATASET_REACHABLE_MAX = {r['DATASET_REACHABLE_MAX']:.12f}（全部真实pair的精确数值最大值）；OBSERVED_MAX = {r['OBSERVED_MAX']:.12f}（已准入候选的成员评分）；threshold = .65。",
        '所有五家族强度均按合法cap同时理想化的0.968只是放宽上界：source=1在空独立性映射的当前recipe中不合法，不冒充可达分数。冻结recipe中source unavailable；metadata可合法不可用（无rule/signature且category unknown），A=.86，其余家族趋近1时得到.951。若metadata可用，cap=.2，A=.9，其余家族趋近1的条件上确界为.930688888889。缺失metadata反而可能增大quality，这也是不能套固定缺项失分模型的原因。',
        '全部真实pair上界搜索、剪枝证明、实际调用scorer次数、最大值见score_reachability.json.dataset_max_certificate。剪枝只计算保守界，不替代正式评分。包含未进入candidate的pair、无效成员和同去重组pair；因此低于阈值足以证明当前输入中正式edge不可达，且不能据此声称没有攻击关系。',
        f"完整同向端点+无传播/兼容pivot条件时，即使time=1、entity=1、metadata=.2、无惩罚，上界也仅 {r['complete_same_direction_endpoint_ceiling']:.12f}。这解释用户X→Y两次告警例子的结构限制；合理演进不是可凭文字补入的关系字段。",
        '## 字段覆盖与损失定位',
        '| 字段 | raw可用 | Canonical/直接raw读取可用 |', '|---|---:|---:|']
    for x in c['fields']:
        lines.append(f"| {x['field']} | {x['raw_available']}/{c['raw_alert_count']} | {x['canonical_available']}/{c['raw_alert_count']} |")
    lines += ['原生全部键路径计数、vendor类别计数、规范类别计数见score_member_coverage.json。proto/flow_id/tx_id虽然不是Canonical独立字段，保存在raw并被正式观察身份/网络核验读取，不能判为Adapter丢失。HTTP hostname保留为DOMAIN，不可无资产证明改称HOST；URL中的cmd.exe文本不是已观测的进程执行/命令实例。原始payload/packet不解码发展为独立日志检测。',
        f"规范类别：{json.dumps(c['canonical_category_counts'])}。真实t5未提供host/account/session/process/lineage；Frozen Suricata原生adapter不输出这些关系。web_attack/unknown不能组成v4要求的不同已知兼容类别转换，所以网络家族没有非零强度。vendor类别到unknown的覆盖限制是Mapping诊断，不等于已证明存在合法隐藏传播关系。",
        '## pair家族覆盖（Top100精确；全量口径单列）',
        '| 家族 | 可用pair比例 | 实际非零比例 | 最大实际贡献 |','|---|---:|---:|---:|']
    for x in p['top100_family_coverage']:
        lines.append(f"| {x['family']} | {x['available_pair_ratio']:.2%} | {x['nonzero_pair_ratio']:.2%} | {x['max_observed_contribution']:.12f} |")
    lines += [p['caveat'],
        '| 全量口径 | 家族 | 可用pair数/比例 | 非零pair数/比例 |',
        '|---|---|---:|---:|']
    for x in p['all_scored_family_coverage']:
        lines.append(f"| {x['population']} | {x['family']} | {x['available_pair_count']}/{x['denominator']} ({x['available_pair_ratio']:.4%}) | {x['nonzero_pair_count']}/{x['denominator']} ({x['nonzero_pair_ratio']:.4%}) |")
    lines += [
        '## Top100及10组逐对下钻',
        'top100_score_breakdown.json保存每对未舍入分数、正方向阈值差`0.65-score`、全部家族贡献/维度状态、实体角色/频率、原始指针验证和单家族乐观敏感性界。敏感性界不回写scorer，不把假设强度当成原始证据。',
        'pair_drilldown.json按同向端点、不同signature、不同观察身份及时间距离选10组，包括完整原始wrapper/_raw/EVE与locator、Canonical provenance、候选提名原因及A–F逐项归因。选择只代表值得调查的连续性，不把相同攻击过程当成已证事实。',
        '| rank | score | .65-score | gate |','|---|---:|---:|---|']
    for x in top:
        lines.append(f"| {x['rank']} | {x['final_score']:.12f} | {x['threshold_gap']:.12f} | {x['gate_reason']} |")
    lines += ['全部Top100没有可从现有raw简单补抽、且单家族足以合法过阈值的遗漏证据。Topology=0是最重的缺口，source不是唯一原因。Relation缺失并非直接禁止无向边；当relation家族可观测却不匹配时，.36权重仍在quality分母中，对只有实体/时间连续性的完整端点数据造成结构性上限。',
        '## Source对照',
        'source不是硬条件，也不要求不同namespace；只改namespace不能证明独立。当前冻结mapping无独立性规则，Suricata→Suricata、Suricata→Wazuh/EDR的source raw strength都为0。跨源还会使rule/signature字符串比较不适用，可能损失metadata，而非固定加.10。若未来有合法独立映射，正source的实际增量还取决于A变化；不能把配置weight=.1误写成固定分差。本次没有修改或临时注入映射。',
        '配置中的同sensor/unknown/same-origin为0；通过全部独立性/上下文/侧面门槛后，同类型独立设备raw S=.2，不同类型未列表=.3，Suricata+EDR=.9，IDS+EDR=.8，Wazuh+AMiner=.7，WAF+Wazuh=.8，WAF+EDR=1。当前空映射使这些非零分支均不可达。Source由unavailable变available时，最终分差为 `.65*((M+.1*s)/(A+.1)-M/A)+.035*s`，并非固定正奖励；低强度甚至可能因quality分母增长而降低总分。',
        '| 严格namespace对照 | same | cross | delta |','|---|---:|---:|---:|']
    for name in ('complete_endpoints','sparse','conditional_flow','unknown_metadata'):
        x=f[name+'_comparison']
        lines.append(f"| {name} | {x['same_source_score']:.12f} | {x['cross_source_score']:.12f} | {x['difference']:.12f} |")
    lines += ['complete_endpoints和sparse均经正式SuricataAdapter/Extraction/scorer，使用已存在CPTC ingestion mapping，只有第二条source_namespace变化，部署scope保持相同。sparse缺dst_ip是合法可选字段诊断，不是CPTC实际字段条件；其合法高分证明算法没有普遍单源禁令，不能拿来解释当前完整端点t5可达。unknown_metadata另外显示：跨namespace后rule/signature不比较且category unknown，metadata家族从AVAILABLE_MISMATCH变UNAVAILABLE，A从.54降到.50，最终分数增加但source仍为0。这是评分可用性引出的跨源偏差，不是独立来源奖励或跨源硬依赖。',
        'conditional_flow仅是Canonical层受控测试，演示同源兼容类别+有序dst→src可以达到阈值，冻结Suricata mapping并不产出其类别；不冒充native输入支持或attested ChainEdge。要求“原生Suricata+完整端点+真实方向relation+其他当前字段不变”的最佳fixture约束在此冻结提取链不可同时满足，不能伪造关系来交付一个虚假的最优数。',
        f"通用Canonical同源/跨源理论上确界相同：{r['same_source_score_supremum']:.12f}。冻结native Suricata路径没有attested关系且无正network类别转换，因此同源/跨源的native上确界均为.825（稀疏拓扑与metadata不可用，T/E趋近1）；native sparse受控可达见证为 {f['sparse_same']['score']:.12f}，它是实际可达见证而非全局最大值。",
        '## 单源全量统计', '```json\n'+json.dumps(p['populations'],indent=2)+'\n```',
        f"成员比较p95={p['same_source_p95']:.12f}，p99={p['same_source_p99']:.12f}。当前最终计数取代早期约950,000进度值。原快照/既有Top100/compact store均只读校验。",
        '## 复现与验证',
        'Python 3.11：`.venv/Scripts/python.exe scripts/cptc_diagnostic_12.py`。仅重生成已有证书的报告：追加`--refresh`；不把refresh称为重跑全量上限搜索。测试：`.venv/Scripts/python.exe -m pytest backend/tests/test_cptc_diagnostic_12.py -q`。回归结果见regression_tests.xml；诊断结果见diagnostic_tests.xml。',
        '## Q1–Q6与结论', '```json\n'+json.dumps(r['questions'],ensure_ascii=False,indent=2)+'\n```',
        'Q2明细：time缺失会隔离；entity缺失类型移出类型分母，家族完全缺失移出A，但W不变；attested relation缺失通常不加分，network AVAILABLE_MISMATCH继续占A；metadata缺失/不可比较移出其可用字段集合，最终cap=.2；source unknown/same-origin移出A，仍不补mass。故“永久损失固定权重”不是当前完整公式，固定mass与可用零分分母的结构限制确实存在。',
        'Q6主因是Dataset evidence limitation + Score reachability design，次因是Mapping覆盖限制。没有证据把Top100零边归因于可恢复的Adapter/Entity丢失；当前数据全部pair最大分证书排除了Candidate omission作为产生正式边的原因。单源并非一般硬门槛；当前冻结独立映射甚至不奖励只改名的跨源。',
        'DIAGNOSTIC_12_RESULT = MIXED_CAUSE',
        '最终结论：当前CPTC t5在现有真实字段及冻结recipe下0.65不可达；原因是数据证据与v4对完整同向网络观察的评分限制共同作用，不是跨源硬依赖。原生单源稀疏合法输入可以超过0.65，但不能用其不同字段条件替代t5结论。所有问题仅记录，未修复。']
    (OUT/'DIAGNOSTIC_REPORT.md').write_text('\n\n'.join(lines)+'\n',encoding='utf8')


if __name__=='__main__':
    main()

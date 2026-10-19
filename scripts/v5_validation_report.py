"""Offline validation aggregations. Semantic labels never feed score functions."""
from bisect import bisect_right
from collections import Counter, defaultdict, deque
import json

import v5_design_diagnostic as d
import v5_validation_evidence as ev
from app.utils.stable_id import raw_fingerprint


def qualify_sparse(out):
    """Audit canonical-sparse records against unchanged original alert snippets.

    Attached content is inspected only to distinguish extraction coverage from
    raw missingness. It never supplies new scoring fields or external logs.
    """
    source=out/'sparse_sample_manifest.json'
    if not source.exists():return dict(canonical_sparse=0,verified_raw_sparse=0,records=[])
    manifest=d.read(out/'canonical_sparse_sample_manifest.json') if (out/'canonical_sparse_sample_manifest.json').exists() else d.read(source)
    records=manifest.get('records',[])
    review_path=out/'raw_sparse_agent_review.json'
    review=d.read(review_path) if review_path.exists() else dict(records=[])
    approved={r['alert_id']:r for r in review['records'] if r.get('decision')=='RAW_SPARSE_CONFIRMED'
              and r.get('evidence_scope')=='frozen_v4_dependency_fields'}
    by_path=defaultdict(dict)
    for row in records:by_path[row['path']][row['ordinal']]=row
    audited=[]
    from build_ait_ads_slices import records as read_records
    for reference,wanted in sorted(by_path.items()):
        path=d.ROOT/reference
        iterator=((r.ordinal,r.eve) for r in d.read_cptc_file(path)) if reference.endswith('.gz') else enumerate(read_records(path),1)
        for ordinal,raw in iterator:
            if ordinal not in wanted:continue
            row=wanted[ordinal]
            if raw_fingerprint(raw)!=row['raw_fingerprint']:
                raise ValueError('raw_sparse_locator_fingerprint_mismatch')
            snippets=raw.get('LogData',{}).get('RawLogData',[])
            attached=[i for i,s in enumerate(snippets) if isinstance(s,str) and s.strip()]
            annotation=approved.get(row.get('alert_id'))
            verified=bool(annotation and annotation['raw_fingerprint']==row['raw_fingerprint']
                and annotation['path']==reference and annotation['ordinal']==ordinal)
            # A nonempty raw snippet may carry source/destination/request/host
            # context unsupported by the confirmed adapter. Do not certify lack.
            status='RAW_SPARSITY_UNVERIFIED_ATTACHED_CONTEXT' if attached else 'RAW_SPARSITY_REQUIRES_SCHEMA_REVIEW'
            audited.append(row | dict(raw_sparsity_status='RAW_SPARSE_CONFIRMED_FOR_FROZEN_DEPENDENCIES' if verified else status,verified_real_sparse=verified,
                attached_evidence_pointers=[f'/LogData/RawLogData/{i}' for i in attached],
                missing_in_raw='SCORING_CONTEXT_FIELDS_ABSENT_IN_REVIEWED_RAW' if verified else 'NOT_ESTABLISHED',
                normalization_failed=False if verified else 'NOT_ESTABLISHED',
                agent_review=annotation,
                extraction_coverage='CANONICAL_CONTEXT_ABSENT; attached raw context requires separate review',
                scoring_effect='NONE; no new extraction or source incapability assumed'))
    confirmed=[r for r in audited if r['verified_real_sparse']]
    result=dict(canonical_sparse=len(records),verified_raw_sparse=len(confirmed),records=audited,
        status='REAL_SPARSE_SAMPLE_FOUND_IN_FROZEN_EVIDENCE_SCOPE' if confirmed else 'REAL_SPARSE_SAMPLE_NOT_FOUND_IN_AVAILABLE_DATASETS',
        limitation='Raw sparsity is certified only for explicit post-score reviewed records under frozen dependencies; the rest remain unverified. No field deletion or snippet-to-score expansion allowed.')
    d.atomic_json(out/'canonical_sparse_sample_manifest.json',result)
    d.atomic_json(source,dict(status=result['status'],count=len(confirmed),records=confirmed,
        canonical_sparse_audit_ref='canonical_sparse_sample_manifest.json',limitation=result['limitation']))
    return result


def stats(rows, key):
    values=[r['v4_score'] if key=='V4_BASELINE' else r['prototypes'][key]['score'] for r in rows]
    return dict(count=len(values),quantiles=d.quantiles(values),ge_065=sum(v>=.65 for v in values),
        admitted=sum(r['v4_valid'] and r['v4_score']>=.65 if key=='V4_BASELINE'
                     else r['prototypes'][key]['admitted'] for r in rows),
        delta=d.quantiles([0 if key=='V4_BASELINE' else r['prototypes'][key]['score_delta_vs_v4'] for r in rows]))


def cluster_evidence(rows):
    """Observed undirected components; no Incident/ChainNode/ChainEdge creation."""
    adjacency=defaultdict(set);edge_ids=defaultdict(list)
    for r in rows:
        if not r['correlation_supported']:continue
        a,b=r['pair'];adjacency[a].add(b);adjacency[b].add(a)
        edge_ids[tuple(sorted((a,b)))].append(r['candidate_id'])
    remaining=set(adjacency);clusters=[]
    while remaining:
        first=min(remaining);todo=[first];component=set()
        while todo:
            a=todo.pop()
            if a in component:continue
            component.add(a);todo.extend(sorted(adjacency[a]-component))
        remaining-=component
        edges=[ids[0] for (a,b),ids in edge_ids.items() if a in component and b in component]
        if len(edges)<2:continue
        # A BFS predecessor path is an actual simple path, not an assertion of
        # maximum Hamiltonian path or attack chronology in a cyclic component.
        best=[]
        for start in sorted(component):
            parents={start:None};q=deque([start])
            while q:
                node=q.popleft()
                for neighbor in sorted(adjacency[node]):
                    if neighbor not in parents:parents[neighbor]=node;q.append(neighbor)
            for end in sorted(component):
                path=[];node=end
                while node is not None:path.append(node);node=parents[node]
                if len(path)>len(best) or (len(path)==len(best) and path<best):best=path
        clusters.append(dict(potential_chain_cluster=True,alert_ids=sorted(component),candidate_ids=sorted(edges),
            edge_count=len(edges),witness_path=best,witness_path_edges=len(best)-1,
            status='CORRELATION_SUPPORTED',progression='CHAIN_PROGRESSION_NOT_YET_SUPPORTED',
            longest_path_status='BFS_WITNESS_LOWER_BOUND_NOT_EXACT_LONGEST_SIMPLE_PATH',
            duplicate_contamination='equivalent observations excluded by frozen matcher',
            limitation='Provisional step compatibility does not prove a common true campaign or directional transitions.'))
    return dict(clusters=clusters,potential_multi_edge_clusters=len(clusters),
        longest_semantically_plausible_candidate_path_edges=max((c['witness_path_edges'] for c in clusters),default=1 if edge_ids else 0),
        path_measure='observed undirected witness, not directional chain',
        directional_progression_pairs=sum(r['chain_progression_supported'] for r in rows))


def finish(cards, views, profiles, caps, policy, out):
    def save(name,value):d.atomic_json(out/name,value)
    sparse_qualification=qualify_sparse(out)
    # Select a finite review front page with source diversity and original score
    # strata. Every other scored row is still retained in the checkpoint.
    top=[];selected=set()
    def take(rows,count,rank):
        for r in sorted(rows,key=rank):
            if r['candidate_id'] not in selected:
                top.append(r);selected.add(r['candidate_id']);count-=1
                if count==0:break
    for dataset in profiles:
        rows=[r for r in cards if r['dataset']==dataset]
        take(rows,50,lambda r:(-r['prototypes']['b']['score'],r['candidate_id']))
        take([r for r in rows if .60<=r['prototypes']['b']['score']<.70],10,
             lambda r:(abs(r['prototypes']['b']['score']-.65),r['candidate_id']))
        take([r for r in rows if .3<=r['prototypes']['b']['score']<.6],10,lambda r:r['candidate_id'])
        take([r for r in rows if r['prototypes']['b']['score']<.3],10,lambda r:r['candidate_id'])
    take([r for r in cards if 'prior_top100_b' in r['selection_strata']],100,
         lambda r:(-r['prototypes']['b']['score'],r['candidate_id']))
    save('top_candidate_review.json',dict(status='PARTIAL_REVIEW_SET',reviewer='agent evidence rubric, provisional; no independent human or GT adjudication',
        selection='50 highest B per dataset + near/medium/low strata + previous B Top100; deduplicated',
        reviewed_count=len(top),relations=dict(Counter(r['semantic_relation'] for r in top)),cards=top))
    positive=[r for r in cards if r['correlation_supported']]
    # Incidental is evidence against pair-level correlation at this scope,
    # not verified campaign ground truth. Shared-IP and repeated observation
    # controls are reported separately and are NOT forcibly negative labels.
    negative=[r for r in cards if r['semantic_relation'] in ('UNRELATED','INCIDENTAL_SIMILARITY')]
    controls=[r for r in cards if any(s.startswith('N') and s[1:2].isdigit() for s in r['selection_strata'])]
    repeated=[r for r in cards if r['semantic_relation']=='REPEATED_OBSERVATION']
    uncertain_high=[r for r in cards if r['semantic_relation']=='UNCERTAIN' and any(r['prototypes'][k]['score']>=.65 for k in d.CANDIDATES)]
    save('uncertain_high_score_audit.json',dict(status='NEEDS_ADJUDICATION',count=len(uncertain_high),
        by_formula={k:dict(raw_high=sum(r['prototypes'][k]['score']>=.65 for r in uncertain_high),
            admitted=sum(r['prototypes'][k]['admitted'] for r in uncertain_high)) for k in d.CANDIDATES},
        cards=sorted(uncertain_high,key=lambda r:(-r['prototypes']['b']['score'],r['candidate_id'])),
        limitation='Routine package-management/user-agent and IDS/TLS pairs lack demonstrated attack progression. They are neither certified positives nor verified campaign negatives. Admission here remains a material review blocker.'))
    save('positive_semantic_review.json',dict(status='PARTIAL_REVIEW_SET',count=len(positive),cards=positive,
        limitation='Provisional SAME_ATTACK_STEP is compatible observed attempts, not confirmed successful attack or independent human truth.'))
    control_stats={}
    for i in range(1,9):
        name=f'N{i}'
        rows=[r for r in controls if any(s.startswith(name+'_') for s in r['selection_strata'])]
        control_stats[name]=dict(count=len(rows),semantic_relation_counts=dict(Counter(r['semantic_relation'] for r in rows)),
            score_comparison={k:stats(rows,k) for k in ('V4_BASELINE',*d.CANDIDATES)},
            candidate_ids=[r['candidate_id'] for r in rows],
            correlation_negative_claim='Only provisional incidental/unrelated subset; N3-N6 are stress controls, not automatically unrelated.')
    save('negative_controls.json',dict(status='PARTIAL_REVIEW_SET',controls=control_stats,
        scored_controls=len(controls),provisional_correlation_negatives=len(negative),
        repeated_observation_chain_controls=len(repeated),cards=negative,
        ground_truth_used_for_scoring='NO',limitations=['No campaign labels; controls cannot supply full-dataset FPR/recall/AUC.']))
    summaries={k:dict(positive=stats(positive,k),negative=stats(negative,k),
        all_reviewed=stats(cards,k),by_completeness={level:stats([r for r in cards
            if r['alert_a']['evidence_completeness']==level and r['alert_b']['evidence_completeness']==level],k)
            for level in ('HIGH','MEDIUM','SPARSE')}) for k in ('V4_BASELINE',*d.CANDIDATES)}
    for k in summaries:
        neg=sorted(r['v4_score'] if k=='V4_BASELINE' else r['prototypes'][k]['score'] for r in negative)
        summaries[k]['semantic_ordering_violations']=sum(len(neg)-bisect_right(neg,
            r['v4_score'] if k=='V4_BASELINE' else r['prototypes'][k]['score']) for r in positive)
        summaries[k]['ordering_comparisons']=len(positive)*len(negative)
    save('prototype_score_comparison.json',dict(status='PARTIAL_REVIEW_SET',positive_count=len(positive),negative_count=len(negative),
        candidates=summaries,ROC_AUC=None,PR_AUC=None,
        metric_status='unavailable: selected provisional review set; incomplete independent labels',
        original_formula_names=policy['formulas'],threshold=.65))
    audits={}
    for k in d.CANDIDATES:
        ranked=sorted(negative,key=lambda r:(-r['prototypes'][k]['score_delta_vs_v4'],r['candidate_id']))[:100]
        audits[k]=dict(top_100_negative_increases=[dict(candidate_id=r['candidate_id'],dataset=r['dataset'],pair=r['pair'],
            semantic_relation=r['semantic_relation'],reasoning=r['reasoning'],v4_score=r['v4_score'],
            prototype=r['prototypes'][k],selection_strata=r['selection_strata']) for r in ranked],
            distribution=summaries[k]['negative'])
    save('residual_negative_audit.json',dict(status='PARTIAL_REVIEW_SET',candidates=audits,
        reviewed_negative_count=len(negative),negative_semantic_confidence='provisional agent review; no campaign GT'))
    ablations={}
    # Fixed top front page + hard residuals; no re-selection by ablation result.
    ablation_ids=set(selected)|{r['candidate_id'] for r in sorted(negative,
        key=lambda r:(-r['prototypes']['b']['score_delta_vs_v4'],r['candidate_id']))[:100]}
    for family in ('temporal','entity','detector_semantic','role_evidence'):
        changed=[]
        for r in cards:
            if r['candidate_id'] not in ablation_ids:continue
            results=ev.ablate(views[r['candidate_id']],family,policy)
            changed.append(dict(candidate_id=r['candidate_id'],semantic_relation=r['semantic_relation'],
                deltas={k:results[k]['score']-r['prototypes'][k]['score'] for k in d.CANDIDATES},
                admitted={k:results[k]['admitted'] for k in d.CANDIDATES},
                scores={k:results[k]['score'] for k in d.CANDIDATES}))
        aggregates={}
        for key in d.CANDIDATES:
            subsets={'positive':[x for x in changed if x['semantic_relation'] in ('SAME_ATTACK_STEP','ATTACK_PROGRESSION')],
                     'negative':[x for x in changed if x['semantic_relation'] in ('INCIDENTAL_SIMILARITY','UNRELATED')]}
            pos_scores=[x['scores'][key] for x in subsets['positive']]
            neg_scores=sorted(x['scores'][key] for x in subsets['negative'])
            aggregates[key]=dict(**{s:dict(count=len(xs),score_delta=d.quantiles([x['deltas'][key] for x in xs]),
                high_scores=sum(x['scores'][key]>=.65 for x in xs),admitted=sum(x['admitted'][key] for x in xs)) for s,xs in subsets.items()},
                semantic_ordering_violations=sum(len(neg_scores)-bisect_right(neg_scores,v) for v in pos_scores))
        ablations[family]=dict(rows=changed,summary=aggregates)
    ablations['destination_context']=dict(status='NOT_INDEPENDENT_SCORED_FAMILY',
        reason='Destination participates in role-weighted entity/target guard; removing it needs recomputing entity+guard evidence. No fictitious independent vote removed.')
    ablations['transport']=dict(status='NO_INDEPENDENT_WEIGHT',
        reason='Transport contributes observation/flow eligibility and duplicates; not separate positive mass. No misleading zero-weight ablation asserted.')
    save('evidence_ablation.json',dict(scope='score-only diagnostic support removal; contradictions and known guards retained; original alerts unchanged',ablations=ablations))
    chains=cluster_evidence(positive)
    save('potential_chain_clusters.json',chains)
    n_medium=sum(p['completeness'].get('MEDIUM',0) for p in profiles.values())
    canonical_sparse=sum(p['completeness'].get('SPARSE',0) for p in profiles.values())
    n_sparse=sparse_qualification['verified_raw_sparse']
    observed_high_negative={k:summaries[k]['negative']['ge_065'] for k in d.CANDIDATES}
    admitted_negative={k:summaries[k]['negative']['admitted'] for k in d.CANDIDATES}
    # A design may have numerically high nonmatches while gates prevent edges.
    # Disclose both; a material admission failure takes priority over limitations.
    over=any(n>0 for n in admitted_negative.values())
    result='V5_EVIDENCE_VALIDATION_OVER_CORRELATED' if over else 'V5_EVIDENCE_VALIDATION_SOURCE_LIMITED'
    freeze=dict(task_result=result,v5_design_candidate='a/b/c/d retained; no winner selected',
        supported_claims=['Unknown propagation is not a contradiction of undirected correlation.',
            'Observed source/detector profiles differ and require conditional capability metadata.',
            'A-D safety gates must be evaluated independently of normalized scores.'],
        rejected_claims=['High normalized agreement alone establishes sufficient correlation.',
            'Same signature/shared IP/time proves common attack or chain direction.',
            '0/N observations establish vendor-wide unavailable capability.'],
        source_capability_supported=True,source_capability_scope='observed conditional availability only; no schema exclusion attestation',
        missing_vs_unavailable_distinction_supported=False,
        missing_vs_unavailable_evidence='Conceptually distinct; genuine source-wide UNAVAILABLE_BY_SOURCE not empirically attested. Do not mistake normalization coverage for source incapability.',
        positive_semantic_improvement={k:summaries[k]['positive'] for k in d.CANDIDATES},
        negative_inflation={k:dict(raw_high_scores=observed_high_negative[k],admitted_negatives=admitted_negative[k],
            distribution=summaries[k]['negative']) for k in d.CANDIDATES},
        sparse_safety=dict(verified_raw_sparse_alert_count=n_sparse,canonical_sparse_alert_count=canonical_sparse,
            raw_qualification=sparse_qualification['status'] if canonical_sparse else 'NO_CANONICAL_SPARSE',
            observed_canonical_sparse={k:summaries[k]['by_completeness']['SPARSE'] for k in summaries}),
        medium_evidence_behavior=dict(real_alert_count=n_medium,observed={k:summaries[k]['by_completeness']['MEDIUM'] for k in summaries}),
        high_evidence_behavior={k:summaries[k]['by_completeness']['HIGH'] for k in summaries},
        threshold_065_status='INSUFFICIENT_EVIDENCE',formula_freeze_ready=False,
        formula_freeze_recommendation='NOT_READY' if over else 'NEEDS_MORE_EVIDENCE',
        remaining_blockers=['No independent pair/campaign adjudication: PARTIAL_REVIEW_SET only.',
            'No schema/deployment attestation proves any family UNAVAILABLE_BY_SOURCE; no source-specific redistribution can be validated.',
            'Real sparse/medium profiles include routine detector outputs; attack-related sparse/medium positives remain unproven.',
            'Cross-source complementary, independent observations and progression evidence remain insufficient.',
            'High-score UNCERTAIN pairs include routine package/user-agent activity; admitted cases require attack-semantic adjudication.',
            'Fixed selected review-set results do not establish global FPR, recall or calibrated thresholds.'],
        production_v4_modified='NO',production_v5_implemented='NO',ground_truth_used_for_scoring='NO')
    save('formula_freeze_evidence.json',freeze)
    counts=dict(reviewed_candidate_front_page=len(top),reviewed_positive_candidates=len(top),
        semantically_valid=sum(r['correlation_supported'] for r in top),
        repeated_observation=sum(r['semantic_relation']=='REPEATED_OBSERVATION' for r in top),
        unrelated_incidental=sum(r['semantic_relation'] in ('UNRELATED','INCIDENTAL_SIMILARITY') for r in top),
        uncertain=sum(r['semantic_relation']=='UNCERTAIN' for r in top),
        total_pairs_scored=len(cards),positive_count=len(positive),medium_alerts_found=n_medium,sparse_alerts_found=n_sparse,
        canonical_sparse_alerts=canonical_sparse,
        hard_negatives_reviewed=len(negative),stress_controls=len(controls),
        negatives_ge_065_v4=summaries['V4_BASELINE']['negative']['ge_065'],
        negatives_ge_065_v5={k:summaries[k]['negative']['ge_065'] for k in d.CANDIDATES},
        admitted_negatives_v5=admitted_negative,
        potential_multi_edge_clusters=chains['potential_multi_edge_clusters'],
        longest_candidate_path_edges=chains['longest_semantically_plausible_candidate_path_edges'])
    save('summary.json',counts)
    paragraphs=[
        '# V5 Evidence Validation', '', f'Task Result: `{result}`. Formula Freeze: `{freeze["formula_freeze_recommendation"]}`.', '',
        'Production v4 unchanged; production v5 not implemented; ground truth/scenarios not read. Reference threshold remains 0.65. No production edges, incidents, chains or API writes.', '',
        'All labels below are provisional agent evidence-rubric review, not independently adjudicated ground truth. PARTIAL_REVIEW_SET; no full-dataset AUC, precision or recall is claimed. Scores are computed before semantic review and labels never feed nomination, weights, capabilities or scoring.', '',
        '## 1. Why v4 has a ceiling', '',
        'v4 already excludes missing entity dimensions from normalized quality. Its fixed evidence-mass blend still limits low-observability inputs; unproven topology can remain an observable zero-strength family. Full historical t5 maximum 0.4229615236870083 differs from the 10k slice because frequency changes. The previous diagnostic decomposes the 0.951 theoretical supremum. No formula or threshold changed here.', '',
        '## 2. How many top candidates have attack-semantic support', '',
        f'Front page {len(top)} unique reviewed pairs: compatible attack step/progression {counts["semantically_valid"]}, repeated observation {counts["repeated_observation"]}, incidental/unrelated {counts["unrelated_incidental"]}, uncertain {counts["uncertain"]}. Across the entire selected scoring review set, {len(positive)} provisional compatible pairs. See top_candidate_review.json and positive_semantic_review.json.', '',
        '## 3. Repeated observations and incidental similarities', '',
        f'{len(repeated)} evaluated pairs were equivalent observations under the existing matcher. These are negative controls for progression, not necessarily unrelated for correlation. N1-N8 statistics retain scanner/shared-target/hot controls even when their campaign relationship is UNCERTAIN. Complete disjoint actor/target pairs and out-of-window pairs receive provisional INCIDENTAL_SIMILARITY, not invented campaign labels.', '',
        '## 4. Real Medium alerts', '',
        f'{n_medium} naturally occurring canonical records. medium_sample_manifest.json records all IDs, original source locators and fingerprints. No fields were dropped. HIGH/MEDIUM/SPARSE are dependency-coverage profiles, not evidence of attack confidence.', '',
        '## 5. Real Sparse alerts', '',
        f'{canonical_sparse} canonical-sparse records; {n_sparse} raw-evidence-sparse record(s) confirmed by post-score agent inspection under frozen dependency fields. '+
        ('The confirmed NewMatchPathDetector spool-lock alert has timestamp/detector metadata and an opaque queue identifier, but no declared endpoint/host/account/session/process/resource context. Sensor ID and origin-log filename are not execution/target entities. This is one sparse alert, not sufficient for a real sparse/sparse or attack-positive pair experiment. See raw_sparse_agent_review.json and sparse_sample_manifest.json. ' if n_sparse else 'REAL_SPARSE_SAMPLE_NOT_FOUND_IN_AVAILABLE_DATASETS. ')+
        f'The remaining {canonical_sparse-n_sparse} canonical-sparse records are not certified raw-sparse: attached AMiner snippets may contain HTTP request/IP, DNS context or CPU host metadata unsupported by extraction. canonical_sparse_sample_manifest.json audits every original locator/fingerprint and attached-content pointer. No new snippet fields enter scoring. Extraction coverage gaps, missing raw facts and normalization failures are kept distinct.', '',
        '## 6. Source capability', '',
        f'{len(caps)} conditional source_type/event_type/detector_type/schema profiles. Field and family counts/rates are conditioned on that profile and dataset. Zero observed count stays UNKNOWN: adapters describe supported extraction, not an exhaustive vendor schema. No UNAVAILABLE_BY_SOURCE assertion was justified by available schema/deployment attestation. This prevents an unjustified source-capability bonus. See source_capability_matrix.json and observed registry.', '',
        '## 7. Unavailable versus nonmatching', '',
        'Both fields present but nonmatching remains observable disagreement. Missing observation, unknown hypothesis and proven source exclusion are separate states. No real schema exclusion was established, so unavailable_weight=0; missing and unknown weights are separately audited. A-D reuse the existing diagnostic state projection without inventing a new formula. Tests distinguish not-observable from explicit disagreement and forbid automatic confidence credit.', '',
        '## 8. Positive score changes', '',
        'Compatible attempts share a specific HTTP resource/domain, same scoped source and complete target, compatible attack detector semantics, temporal support and distinct observations. They establish plausible common step only; success/causality is unproven. All four existing formula candidates and exact deltas are retained. No named sample, IP, rule or signature changes a scoring weight.', '',
        '## 9. Hard-negative score changes', '',
        'Residual audit retains the Top100 score increases for each A-D formula. All scored incidental controls are kept, including high-score gate rejects. Quantiles and 0.65 raw counts are separate from admitted counts. N3-N6 remain stress cohorts; they are not forced into the negative denominator. Every evidence card resolves raw pointers to the bound original alert.', '',
        '## 10. Over-correlation', '',
        f'Raw negative scores >=0.65: {observed_high_negative}; admitted provisional negatives: {admitted_negative}. '+('Material admission inflation detected.' if over else 'No material admission inflation in this selected provisional incidental subset; this does not establish global absence of false associations.')+f' Separately, {len(uncertain_high)} UNCERTAIN pairs have high raw scores under one or more prototypes; {sum(r["prototypes"]["b"]["admitted"] for r in uncertain_high)} pass B gates. These include routine package/user-agent activity and require adjudication; they are a material freeze blocker, not evidence of clean global precision. See uncertain_high_score_audit.json. Ablations preserve contradictions and known guards while removing positive support and dependency votes. Transport and destination have no independent scored vote; their eligibility effects cannot be honestly represented by a fictitious standalone ablation.', '',
        '## 11. Multi-edge candidates and chain feasibility', '',
        f'{chains["potential_multi_edge_clusters"]} provisional undirected multi-edge components, longest recorded simple BFS witness {chains["longest_semantically_plausible_candidate_path_edges"]} edges. This is a lower bound over reviewed pairs, not an exact longest path or attack-chain length. CORRELATION_SUPPORTED / CHAIN_PROGRESSION_NOT_YET_SUPPORTED. Temporal order plus shared nodes does not establish role transition or propagation. See potential_chain_clusters.json.', '',
        '## 12. Formula Freeze recommendation', '',
        f'{freeze["formula_freeze_recommendation"]}. Current observed capability coverage does not prove unavailable-by-source behavior. Routine sparse/medium alerts do not substitute for adjudicated sparse/medium attack-related positives. Independent semantic adjudication, schema/deployment capability evidence and cross-source/progression examples are still needed. No Formula Freeze performed.', '',
        '## Reproduction and scope', '',
        'Run `.venv/Scripts/python.exe -u scripts/v5_evidence_validation.py` from the root. Only output artifacts are written. Production modules, source data, seven baselines and previous diagnostic artifacts are hashed before and after. Git metadata is absent, recorded explicitly. Full CPTC partitions receive lightweight raw-field profiling only; scoring uses the existing 10k t5 and two existing AIT small slices. Pair selection is bounded, indexed/hash-deterministic; it is a semantic review set, not a complete production candidate experiment. No random retries or outcome-dependent parameter selection. Fox is a fixed validation slice, never used for tuning.', '',
        'Completeness HIGH: complete source/destination/protocol/ports or host+identity+process bundle. MEDIUM: a canonical candidate context exists without that bundle. SPARSE: only detector/time without usable canonical candidate context. Category and detector fields are reported separately, so a generic name cannot manufacture a complete attack profile. This rule follows prerequisites in evidence_v4/evidence_v3/evidence.py and observation matching; it does not add schema fields or production gates.', '',
        'Scoring policy names A/B/C/D, mass/confidence/quorum parameters and frozen penalties are exactly the previous diagnostic policy. UNKNOWN hypotheses remain excluded from Q under that pre-existing candidate definition; absolute confidence gets no credit. This task does not claim to validate a new source-aware denominator when no source exclusion is attested.', '',
        '## Numerical comparison (selected provisional review set)', '',
        '| Formula | Positive n | P50 / P90 / MAX | Negative n | P50 / P90 / P99 / MAX | Negative raw >=.65 / admitted |',
        '| --- | ---: | --- | ---: | --- | --- |']
    def f(value):return 'null' if value is None else f'{value:.6f}'
    for k,s in summaries.items():
        p,n=s['positive'],s['negative'];pq,nq=p['quantiles'],n['quantiles']
        paragraphs.append(f'| {k} | {p["count"]} | '+ ' / '.join(f(pq[x]) for x in ('P50','P90','max'))+
            f' | {n["count"]} | '+' / '.join(f(nq[x]) for x in ('P50','P90','P99','max'))+f' | {n["ge_065"]} / {n["admitted"]} |')
    paragraphs+=['', '## Dataset distributions', '', '| Slice | Raw | Canonical | HIGH | MEDIUM | SPARSE |', '| --- | ---: | ---: | ---: | ---: | ---: |']
    for name,p in profiles.items():
        counts=p['completeness'];paragraphs.append(f'| {name} | {p["raw_count"]} | {p["selected_count"]} | {counts.get("HIGH",0)} | {counts.get("MEDIUM",0)} | {counts.get("SPARSE",0)} |')
    paragraphs+=['', 'All statistical denominators are explicit in JSON; missing/empty metrics are null. Tests and command receipts are in TEST_RESULTS.md after verification.', '',
        'PRODUCTION_V4_MODIFIED = NO', 'PRODUCTION_V5_IMPLEMENTED = NO', 'GROUND_TRUTH_USED_FOR_SCORING = NO', '']
    (out/'V5_EVIDENCE_VALIDATION_REPORT.md').write_text('\n'.join(paragraphs),encoding='utf8')

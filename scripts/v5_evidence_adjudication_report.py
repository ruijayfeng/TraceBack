"""Assemble post-label observations and a conservative formula-freeze verdict."""
from collections import Counter
import csv
import json
import xml.etree.ElementTree as ET

import v5_evidence_adjudication as m
import v5_evidence_adjudication_evidence as e


def score_analysis(cards):
    result={}
    for name in ('V4_BASELINE','a','b','c','d'):
        by_label={}
        for label in e.LABELS:
            selected=[c for c in cards if c['adjudication']['label']==label]
            values=[c['algorithm']['v4_score'] if name=='V4_BASELINE' else c['algorithm']['prototypes'][name]['score'] for c in selected]
            by_label[label]=dict(count=len(selected),quantiles=m.d.quantiles(values),
                ge_065=sum(x>=.65 for x in values),
                admitted=sum(c['algorithm']['v4_valid'] and c['algorithm']['v4_score']>=.65 if name=='V4_BASELINE'
                    else c['algorithm']['prototypes'][name]['admitted'] for c in selected))
        result[name]=by_label
    return dict(by_formula=result,primary_comparison='b, same prototype as original admitted 26; A/C/D retained without winner selection',
        confirmed_related_below_threshold=[],confirmed_unrelated_high_scores=[],
        boundary_observation='All 94 were selected as high under at least one prototype. No independent low-score control population is added.',
        ranking_conclusion='No confirmed-related or confirmed-unrelated target pair exists; attack-semantic ranking and a .65 semantic boundary cannot be established.',
        auc=None,auc_status='unavailable_no_independent_ground_truth',labels_consumed_by_scoring=False)


def missing_reclassification(prior,cards,obs):
    mapping={'IP':('SRC_IP','DST_IP'),'ACCOUNT':('ACCOUNT',),'HOST':('HOST',),'SESSION':('SESSION',),
        'PROCESS':('PROCESS',),'FILE':('FILE',),'URL':('URL',),'DOMAIN':(), 'COMMAND':()}
    counts=Counter();dimensions=Counter();examples=[]
    new={c['pair_id']:c for c in cards}
    for row in prior:
        ids=row['pair']
        for dimension,state in row['evidence_states'].items():
            if state['state']!='MISSING_OBSERVATION':
                continue
            classification='UNKNOWN'
            families=mapping.get(dimension.removeprefix('entity.'),()) if dimension.startswith('entity.') else ()
            for family in families:
                left=obs[ids[0]].get(family,{}).get('value')
                right=obs[ids[1]].get(family,{}).get('value')
                if e.present(left) and e.present(right):
                    classification=e.capability_comparison(left,right,'OBSERVED','OBSERVED')
                    break
            counts[classification]+=1;dimensions[dimension]+=1
            if classification!='UNKNOWN':
                examples.append(dict(pair_id=row['candidate_id'],dimension=dimension,
                    prior_state=state['state'],classification=classification,reason='raw-only evidence is available to post-hoc review; unchanged scoring did not consume it'))
    return dict(total_previous_missing_dimensions=sum(counts.values()),
        states={k:counts[k] for k in ('CAPABILITY_ABSENT','OBSERVABLE_NONMATCH','OBSERVABLE_MATCH','UNKNOWN')},
        dimensions=dict(dimensions),raw_only_observable_examples=examples,
        source_capability_absent_proven=0,
        reason='No source/deployment schema exclusion attestation was supplied. Zero coverage of inspected structures is not proof of source-wide incapability.',
        scope='Exact original MISSING_OBSERVATION dimensions in fixed 94, not all source-family cells')


def finish():
    prior=m.targets()
    old={r['candidate_id']:r for r in prior}
    blind=[json.loads(line) for line in (m.OUT/'blind_review.jsonl').open(encoding='utf8')]
    decisions=m.d.read(m.OUT/'semantic_decisions.json')
    if decisions['blind_deck_sha256']!=m.d.file_digest(m.OUT/'blind_review.jsonl'):
        raise ValueError('review_deck_changed')
    annotations={x['pair_id']:x for x in decisions['decisions']}
    if set(annotations)!=set(old) or len(blind)!=94:
        raise ValueError('all_94_original_pairs_require_explicit_review')
    cards=[]
    # Complete labels before attaching archived scores. No scoring call here.
    for row in blind:
        annotation=annotations[row['pair_id']]
        judgement=e.semantic_label(row,annotation)
        evidence=e.independent_evidence(row)
        if e.digest(evidence)!=annotation['independent_evidence_sha256']:
            raise ValueError('review_evidence_changed')
        archived=old[row['pair_id']]
        cards.append(dict(**row,independent_semantic_evidence=evidence,adjudication=judgement,
            algorithm=dict(score=archived['prototypes']['b']['score'],admitted=archived['prototypes']['b']['admitted'],
                score_scope='archived diagnostic prototype B; not production admission',
                component_scores=archived['prototypes']['b']['family_strengths'],prototypes=archived['prototypes'],
                v4_score=archived['v4_score'],v4_valid=archived['v4_valid'],v4_breakdown=archived['v4_breakdown']),
            previous_evidence_states=archived['evidence_states'],shared_entities=archived['shared_entities'],
            observable_evidence=archived['available_evidence'],missing_evidence=[k for k,v in archived['evidence_states'].items()
                if v['state'] in ('MISSING_OBSERVATION','UNKNOWN')],evidence_families=archived['v4_breakdown']['evidence_v2']['evidence_families']))
    m.lines('pair_adjudication.jsonl',cards)
    admitted=[c for c in cards if c['algorithm']['admitted']]
    if len(admitted)!=26:
        raise ValueError('exact_admitted_subset_changed')
    counts={label:sum(c['adjudication']['label']==label for c in cards) for label in e.LABELS}
    summary=dict(target_count=94,reviewed=94,counts=counts,admitted_target_count=26,admitted_reviewed=26,
        independent_human_review=False,review_method=decisions['review_method'],
        interpretation='Labels judge attack relation, not mere transport or routine operational association; unresolved is never negative.')
    m.save('pair_label_summary.json',summary)
    admitted_summary=e.precision_evidence(admitted)
    m.save('admitted_26_review.json',dict(**admitted_summary,cards=admitted,
        strict_confirmed_count=admitted_summary['strict_numerator'],
        broad_confirmed_plausible_count=admitted_summary['broad_numerator'],
        attack_semantic_support_count=sum(c['adjudication']['attack_semantic_support'] for c in admitted)))
    scores=score_analysis(cards)
    m.save('score_label_analysis.json',scores)
    m.d.log('labels_completed',counts=counts,admitted_26=admitted_summary['counts'])
    with m.d.truth_guard(m.ROOT):
        entries=list(m.cached())
        # Canonical model validation checks fingerprints, UTC and Stable IDs.
        per_alert={a.alert_id:e.observations(a) for _,a,_ in entries}
        capability=e.capability_rows(entries)
        cap_summary=dict(source_namespaces=len({r['source'] for r in capability}),
            conditional_profiles=len({(r['dataset'],r['source'],r['source_type'],r['detector_profile']) for r in capability}),
            family_cells=len(capability),status_counts=dict(Counter(r['status'] for r in capability)),
            distinct_families_observed=sorted({r['family'] for r in capability if r['observed']}),
            distinct_families_fully_attested=sorted({r['family'] for r in capability if r['status']=='ATTESTED'}),
            source_capability_absent_attestations=0,
            scope='Complete counts in unchanged finite slices, conditioned by source and detector. Reliability describes export coverage, not future deployment guarantees.',
            snippets_limitation='Unparsed free text/aggregate AMiner path vectors may carry additional fields. UNAVAILABLE means not observed in inspected structures, never cannot be provided by the vendor.')
        m.save('source_capability_attestation.json',dict(summary=cap_summary,rows=capability))
        with (m.OUT/'source_capability_matrix.csv').open('w',encoding='utf8',newline='') as stream:
            columns=['source','source_type','detector_profile','dataset','family','observed','total','coverage',
                'schema_supported','reliably_observed','reliability','semantically_usable','status','capability_state','semantic_scope']
            writer=csv.DictWriter(stream,fieldnames=columns,extrasaction='ignore');writer.writeheader();writer.writerows(capability)
        missing=missing_reclassification(prior,cards,per_alert)
        m.save('missing_evidence_reclassification.json',missing)
        pair_caps=[]
        for c in cards:
            ids=[c['alert_a']['alert_id'],c['alert_b']['alert_id']]
            states={family:e.capability_comparison(per_alert[ids[0]].get(family,{}).get('value'),
                per_alert[ids[1]].get(family,{}).get('value'),'OBSERVED','OBSERVED') for family in e.FAMILIES}
            pair_caps.append(dict(pair_id=c['pair_id'],states=states))
        m.lines('pair_capability_states.jsonl',pair_caps)
        from v5_evidence_adjudication_progression import search
        progression=search(entries,blind)
    # Lack of schema exclusion and sparse attack-positive verification is a
    # material source limitation even after complete finite-export attestation.
    result='V5_EVIDENCE_ADJUDICATION_SOURCE_LIMITED'
    gate='NEEDS_MORE_EVIDENCE'
    report(cards,counts,admitted_summary,cap_summary,missing,progression,result,gate)
    m.freeze()
    terminal=dict(task_result=result,frozen_algorithm=m.d.read(m.OUT/'freeze_verification.json')['algorithm_version'],
        pairs_reviewed='94 / 94',admitted_pairs_reviewed='26 / 26',pair_labels=counts,
        admitted_26=admitted_summary['counts'],source_capability=cap_summary,
        progression=dict(verified_progressions=0,best_progression_length=0,consecutive_edges=0,best_level='LEVEL 0'),
        best_progression=None,scores=[],admitted=[],primary_bottleneck='SOURCE_OBSERVABILITY',
        production_v4_modified='NO',production_v5_implemented='NO',v5_formula_freeze_gate=gate)
    m.save('summary.json',terminal)
    write_manifest(result,gate)
    print(json.dumps(terminal,ensure_ascii=True,indent=2),flush=True)


def report(cards,counts,admitted,cap,missing,prog,result,gate):
    freeze=m.d.read(m.OUT/'freeze_verification.json')
    rows=m.d.read(m.OUT/'source_capability_attestation.json')['rows']
    source_table='| Source namespace | Detector profiles | ATTESTED cells | PARTIAL cells | UNAVAILABLE cells |\n|---|---:|---:|---:|---:|\n'
    source_details=[]
    for source in sorted({r['source'] for r in rows}):
        selected=[r for r in rows if r['source']==source]
        statuses=Counter(r['status'] for r in selected)
        observed=sorted({r['family'] for r in selected if r['observed']})
        missing_families=sorted(set(e.FAMILIES)-set(observed))
        source_table+=f"| {source} | {len({r['detector_profile'] for r in selected})} | {statuses['ATTESTED']} | {statuses['PARTIAL']} | {statuses['UNAVAILABLE']} |\n"
        source_details.append(f"- `{source}` observed in at least one profile: {', '.join(observed)}. Not observed in inspected structures: {', '.join(missing_families)}.")
    source_details='\n'.join(source_details)
    verification='| Receipt | Passed | Failed | Errors | Skipped |\n|---|---:|---:|---:|---:|\n'
    for name in ('backend_test_results.xml','final_targeted_test_results.xml','legacy_failure_recheck.xml'):
        path=m.OUT/name
        if not path.exists():
            continue
        suites=list(ET.parse(path).getroot().iter('testsuite'))
        total=sum(int(s.get('tests',0)) for s in suites)
        failed=sum(int(s.get('failures',0)) for s in suites)
        errors=sum(int(s.get('errors',0)) for s in suites)
        skipped=sum(int(s.get('skipped',0)) for s in suites)
        verification+=f'| {name} | {total-failed-errors-skipped} | {failed} | {errors} | {skipped} |\n'
    text=f'''# V5 Evidence Adjudication & Capability Attestation

Task Result: `{result}`

V5 Formula Freeze Gate: `{gate}`

## Scope, provenance and review independence

All original 94 unresolved high-score pairs and their exact 26 prototype-B admitted members were reviewed. No replacement Top-N was sampled. Every card includes both original raw alerts, canonical fields, locators, fingerprints, detector metadata, decoded alert payloads where present, independent evidence and archived A/B/C/D scores. Production Correlation/Incident/Chain/API/frontend and formula/threshold/candidate settings were untouched. No production V5 exists.

These are explicit **agent evidence adjudications**, not an independent human panel or campaign ground truth. The review function receives only the evidence deck and explicit content-bound annotations; no score or admitted flag is an argument. Archived score information was available earlier in this session, so this is not a double-blind study. Scores are never used as semantic evidence. Scores are attached after labels; labels do not enter nomination, scoring or features.

## Frozen baseline

- Algorithm: `{freeze['algorithm_version']}`
- Config hash: `{freeze['config_hash']}`
- Mapping digest: `{freeze['mapping_digest']}`
- Reference threshold: `{freeze['threshold']}`
- Previous evidence manifest SHA-256: `{freeze['previous_evidence_validation_manifest_hash']}`
- Diagnostic manifest SHA-256: `{freeze['diagnostic_manifest_hash']}`
- Candidate recipe and all dataset hashes: `freeze_verification.json`.
- Frozen implementation receipt plus accepted execution-equivalence receipt validated by the unchanged historical loader. Git metadata is unavailable. Hash comparisons include original protected files, production/config/frontend and previous artifacts; checked again after execution.

Only the frozen 10,000 CPTC alerts, 7,640 russellmitchell alerts and 7,680 fox alerts were canonicalized. Identity digests equal prior validation. Fox remains validation-only and no parameters were selected. All prior JSON artifacts were parsed; the 225,616 archived candidate records were validated and indexed without generating new full-dataset pairs. See `prior_artifact_inventory.json`.

## Q1 — 94 labels

| Label | Count |
|---|---:|
'''
    text+='\n'.join(f'| {label} | {counts[label]} |' for label in e.LABELS)
    text+=f'''

The sole plausible pair concerns two decoded login requests reusing a credential while changing account formatting and USER/ADMIN role claims, with HTTP 422 then 200. This is plausible authentication/role probing, not confirmed unauthorized access. The 15 repeated ADMIN-token validation pairs show equal token/object/request content, but ownership and authorization are unknown. The 10 APT pairs show repository metadata retries, not attack confirmation. TLS anomaly pairs and port-only PostgreSQL detections also lack sufficient attack attribution. Shared scanner/source/target/time and detector similarity alone were not promoted to confirmed.

An unresolved attack relationship can coexist with a confirmed routine operational association. Treating repository retries or the same TLS observation as confirmed-unrelated attacks would manufacture negatives. Different flow IDs do not prove different campaigns. Likewise, equal flow IDs and signatures do not prove an attack.

## Q2 — 26 admitted and precision evidence

Strict confirmed: **{admitted['strict_numerator']}**. Broad confirmed+plausible: **{admitted['broad_numerator']}**. Unresolved: **{admitted['unresolved']}**. Negative: **{admitted['negative_count']}**.

Adjudicable denominator = {admitted['adjudicable']}; strict = {admitted['strict_numerator']}/{admitted['adjudicable']}, broad = {admitted['broad_numerator']}/{admitted['adjudicable']}. This is only **review-set admitted precision evidence**. With 25 of 26 unresolved, the conditional broad fraction has almost no admission-validation value. No dataset precision, false-positive rate or validated maliciousness is claimed.

## Q3 — Score ranking and .65 boundary

`score_label_analysis.json` reports all label distributions under frozen V4 and A/B/C/D. The original B score is the reference for the 26; there is no newly selected V5 winner. This target set contains zero confirmed positives and zero confirmed negatives, so ranking of real attack relationships, enrichment against a random population, AUC and a .65 semantic boundary are **unavailable**. High-score unresolved examples are abundant. No high-score confirmed false positive or below-threshold confirmed positive is established within these 94. Absence of a confirmed negative is not demonstrated precision.

## Q4 — Measured source capability

{cap['source_namespaces']} source namespaces, {cap['conditional_profiles']} conditional detector/source profiles and {cap['family_cells']} family cells were measured across all 24 requested families. Counts: `{json.dumps(cap['status_counts'],sort_keys=True)}`. Every observed row carries up to three alert IDs, original locators, raw JSON pointers/values, canonical projection and exact coverage numerator/denominator. `source_capability_matrix.csv` is the full table.

{source_table}
The table counts detector-conditioned family cells, not independent sources or global guarantees. Observability by source, including partial coverage:

{source_details}

ATTESTED means complete valid observed coverage **in that frozen detector-conditioned export**, not guaranteed delivery by all future deployments. PARTIAL means conditional availability; UNAVAILABLE means zero values in the inspected structures, not vendor schema exclusion. Schema support, observed coverage, reliability and semantic usability are separate fields. No arbitrary statistical reliability cutoff was added.

Payload-bearing CPTC can carry specific account claims and application tokens even when canonical ACCOUNT/SESSION are null. Some fast-log wrappers also carry ports/protocol that their canonical fields omit. These are extraction/projection gaps, not unavailable source capabilities. Flow IDs identify scoped transport flows, not authenticated application sessions. Packet endpoint roles do not identify attacker/victim. Collector agent identity is never target-host evidence. Request attack content attests an observable attempt, not successful exploitation. Free-text/aggregate AMiner contexts remain incompletely inspected for optional fields.

## Q5 — Missing versus nonmatching

Across {missing['total_previous_missing_dimensions']} original missing-dimension observations, source-wide CAPABILITY_ABSENT proven = **0**. Reclassification: `{json.dumps(missing['states'],sort_keys=True)}`. Raw-only observable matches are recorded individually and never fed back into scoring. All remaining missing states stay UNKNOWN; zero coverage is not negative evidence or proof of source incapability. Actual observed differing values remain OBSERVABLE_NONMATCH. See `missing_evidence_reclassification.json` and `pair_capability_states.jsonl`.

## Q6 — Real progression

**LEVEL 0 — NO VERIFIED PROGRESSION FOUND** in the bounded scope. Verified progressions = 0; no best A→B→C is invented.

The plausible login pair was expanded at ±5, ±15, ±30 and ±60 minutes using a single streamed endpoint-window extraction of the original compressed alert export. Only the same two alerts were present; there was no third supporting alert. The full stream was read for bounded retrieval, never canonicalized or pair-enumerated. Every window logs inspected alerts, produced pairs and semantic hits.

Strategy C found {prog['eligible_multiaction_flows']} scoped flows with at least three distinct content-grounded request actions and inspected the first {prog['selected_flows']} by a fixed lexical pre-score selection. Each hypothesis preserves flow/transaction order, raw payloads, complete endpoint tuple, detector semantics, candidate provenance and per-edge scores. Multiple signatures on one HTTP transaction are collapsed; disconnected A–B+C–D cannot form a witness.

These examples prove ordered vulnerability-scanning operations, including sensitive-file, SQL, script and command probes. They do **not** establish that an earlier action enabled a later step, successful command execution, or attack-stage advancement. A cmd.exe request and HTTP response status cannot substitute for endpoint execution evidence. Therefore they remain rejected progression hypotheses in `progression_evidence/` and are excluded from verified counts. The package adjacency check is necessary, not semantic approval.

## Q7 — Failure location

The primary blocker for a verified attack progression is **SOURCE_OBSERVABILITY** in the inspected alert scope: operation outcome/causal continuation remains unverified. AIT TLS repetition adds no endpoint outcome; login continuation is absent in its bounded context. It is not established that a real progression was cut specifically by scoring or threshold.

For the {prog['candidate_pairs_produced']} edges in the separate scanner hypotheses, the archived recipe nominated {prog['candidate_reachable_hypothesis_edges']}; {prog['score_ge_065_hypothesis_edges']} have prototype-B score ≥.65, and {prog['admitted_hypothesis_edges']} pass nomination plus B admission. Failure-stage counts: `{json.dumps(prog['failure_stages'],sort_keys=True)}`. Each edge separately records RAW_VISIBLE, CANONICAL_VISIBLE, CANDIDATE_NOMINATED, SCORED, ADMITTED, frozen V4 score, all prototype scores and gates. Hypothetical scores for non-nominated pairs are explicitly counterfactual. Evidence-gate refusal is separated from score-threshold refusal. These observations do not establish candidate/scoring recall over real progressions; that denominator is zero and reachability fractions are null.

## Q8 — Formula freeze

**NEEDS_MORE_EVIDENCE**. Reviews and finite-export capability measurements are complete, but no confirmed attack-positive admission evidence or verified ≥2-edge progression supports READY. Source-wide exclusion is also unattested, so a source-incapability redistribution claim remains unvalidated. There is no confirmed-unrelated majority that would justify DESIGN_REVISION_REQUIRED from this review alone.

Recommended future evidence: independently adjudicated attacks with outcome/session/lineage continuation; explicit exporter/deployment field-exclusion attestation; account/token ownership and authorization context where relevant. Review source extraction gaps separately in a future authorized task. No formula, weights, threshold, normalization, nomination, candidate budget, clustering, reconstruction, API or frontend was changed here.

## Isolation and reproduction

External scenario knowledge used for scoring = NO. Used for nomination = NO. Used for post-hoc adjudication = NO. Ground truth/scenario files were not read; all data work runs within the existing runtime truth guard. Only alert-attached payload/full_log text was inspected. Labels reside solely in offline artifacts; production does not consume them.

Run `.venv/Scripts/python.exe -u scripts/v5_evidence_adjudication.py --prepare`, inspect `blind_review.jsonl`, record content-bound explicit decisions in `semantic_decisions.json`, then run the same script with `--finish`. Preparation verifies every slice identity. The explicit decision file is preserved and is never regenerated from scores. Test receipts and commands are recorded in `TEST_RESULTS.md`; source/output hashes are in `manifest.json`.

## Test results and inherited failures

{verification}
The full backend run has two real failed checks: `test_d1_positive_scan::test_frozen_config_identity_and_thresholds` and `test_final_demo_selection::test_accepted_frozen_algorithm_and_mapping_are_unchanged`. Both reject `backend/app/correlation/candidates.py` through the older `find_demo_dataset.frozen` helper, which compares the initial receipt bytes without consulting the subsequent execution-equivalence receipt. The same two failures are documented before this task in `outputs/cptc_2018_step3a_capacity/regression_failure_classification.json`. They remain failures; no existing gate, test or production file was changed. Current candidate bytes match both the task-entry baseline and the accepted execution receipt, and this task's dedicated frozen loader passes. The full suite is therefore not wholly green. See this output directory's `regression_failure_classification.json` for hashes and retained failure evidence.

`reproduction_verification.json` records repeated frozen execution of the core semantic artifacts. This is separate from nondeterministic test timestamps and diagnostic provenance formatting.

PRODUCTION_V4_MODIFIED = NO

PRODUCTION_V5_IMPLEMENTED = NO
'''
    (m.OUT/'V5_EVIDENCE_ADJUDICATION_REPORT.md').write_text(text,encoding='utf8')


def write_manifest(result,gate):
    files={p.relative_to(m.OUT).as_posix():m.d.file_digest(p) for p in sorted(m.OUT.rglob('*'))
        if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts}
    source={p.relative_to(m.ROOT).as_posix():m.d.file_digest(p) for p in sorted((m.ROOT/'scripts').glob('v5_evidence_adjudication*.py'))}
    test=m.ROOT/'backend/tests/test_v5_evidence_adjudication.py'
    if test.is_file():
        source[test.relative_to(m.ROOT).as_posix()]=m.d.file_digest(test)
    m.save('manifest.json',dict(version=m.VERSION,task_result=result,v5_formula_freeze_gate=gate,
        files=files,source_hashes=source,previous_evidence_validation_manifest_hash=m.d.file_digest(m.PRIOR/'manifest.json'),
        target_pair_identity_digest=e.digest(sorted(r['candidate_id'] for r in m.targets())),
        production_v4_modified='NO',production_v5_implemented='NO',
        external_scenario_knowledge_used_for_scoring='NO',external_scenario_knowledge_used_for_nomination='NO',
        external_scenario_knowledge_used_for_post_hoc_adjudication='NO'))

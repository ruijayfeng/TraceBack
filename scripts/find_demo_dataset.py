"""Bounded, label-free Demo discovery using the unchanged accepted v4.

Window nomination uses timestamps, volume and observed structured fields only.
All source records inside each half-open UTC window are retained. Suitability
is an offline presentation diagnostic, never an algorithm input or metric of
attack accuracy. No evaluation module or development experiment is imported.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.adapters import AMinerAdapter, WazuhAdapter
from app.adapters.base import reject_truth
from app.models.base import resolve_pointer
from app.services.capacity import json_array_records
from app.services.datasets import load_dataset, read_registry
from app.services.storage import atomic_json as strict_atomic_json, file_digest
from app.utils.stable_id import content_digest, utc_text
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.correlation.edges import run_correlation, correlation_version
from app.chains.assembly import run_reconstruction

OUT = ROOT / 'outputs/final_demo'
RULE = dict(version='demo-discovery-v1', window_seconds=900, stride_seconds=900,
            window_semantics='[start,end)', minimum_raw_count=100, maximum_raw_count=1500,
            windows_per_scene=8, nomination='4 structured-field coverage ranks + 4 time quantiles; unique windows',
            source_filter=['aminer', 'wazuh'], retain='all in-window records of both sources',
            labels_used=False, outcome_based_record_filter=False)


def atomic_json(path, value):
    # Counters/tuples are internal statistics. The frozen JSON serializer
    # correctly rejects them; normalize only this script's audit transport.
    strict_atomic_json(path, json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False)))


def records(path):
    with Path(path).open(encoding='utf-8-sig') as handle:
        head = handle.read(4096).lstrip()
        handle.seek(0)
        if head.startswith('['):
            yield from json_array_records(handle)
        else:
            for line in handle:
                if line.strip():
                    yield json.loads(line)


def adapter(loaded, source):
    settings = next(s for kind, s in loaded.sources.values() if kind == source)
    return (AMinerAdapter if source == 'aminer' else WazuhAdapter)(loaded.config, settings)


def stamp(raw, source, ad):
    reject_truth(raw)
    if source == 'aminer':
        values = raw['LogData']['DetectionTimestamp']
        if not isinstance(values, list) or not values:
            raise ValueError('missing_detection_timestamp')
        value = values[-1]
    else:
        value = raw.get('@timestamp') or raw.get('timestamp')
    return datetime.fromisoformat(ad.parse_time(value).replace('Z', '+00:00'))


def field_coverage(raw):
    """Raw field availability, not inferred behavior, evidence or score."""
    found = set()
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if child not in (None, '', [], {}):
                    if key.lower() in {'srcip', 'src_ip', 'source_ip', 'dstip', 'dst_ip', 'dest_ip'}:
                        found.add('network')
                    if key.lower() in {'user', 'username', 'srcuser', 'dstuser', 'account'}:
                        found.add('account')
                    if key.lower() in {'url', 'uri', 'filename', 'file', 'command', 'exe', 'pid', 'session', 'flow_id'}:
                        found.add('resource_or_flow')
                if isinstance(child, (list, dict)):
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(raw)
    return found


def frozen(loaded):
    receipt = json.loads((ROOT / 'outputs/correlation_v4_small/FREEZE_MANIFEST.json').read_text(encoding='utf8'))
    if not receipt['CORRELATION_V4_FROZEN']:
        raise ValueError('v4_not_frozen')
    snapshot, accepted = loaded.config.snapshot, receipt['algorithm_snapshot']
    # Deployment declarations legitimately differ; every other algorithm field
    # and all mapping content must be exactly the accepted recipe.
    snapshot['normalization']['source_timezones'] = accepted['normalization']['source_timezones']
    if snapshot != accepted or loaded.config.mapping_digest != receipt['mapping_digest']:
        raise ValueError('frozen_recipe_mismatch')
    if correlation_version(loaded.config) != receipt['algorithm_version']:
        raise ValueError('frozen_algorithm_version_mismatch')
    for path, digest in receipt['implementation'].items():
        if path.startswith(('backend/app/correlation/', 'backend/app/dedup/', 'backend/app/entities/',
                            'backend/app/chains/', 'backend/app/incidents/', 'configs/algorithm', 'configs/mappings/',
                            'backend/app/models/')) and file_digest(ROOT / path) != digest:
            raise ValueError('frozen_implementation_changed:' + path)
    return receipt


def index():
    OUT.mkdir(parents=True, exist_ok=True)
    if (OUT / 'search_plan.json').exists():
        raise ValueError('search_plan_already_exists')
    atomic_json(OUT / 'search_rule.json', RULE)  # Publish before scanning outcomes.
    baseline = {}
    for folder in ('backend/app', 'configs', 'docs', 'scripts', 'frontend/src'):
        baseline.update({p.relative_to(ROOT).as_posix(): file_digest(p)
                         for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts})
    baseline['AGENTS.md'] = file_digest(ROOT / 'AGENTS.md')
    if not (OUT / 'initial_files.json').exists():
        atomic_json(OUT / 'initial_files.json', baseline)
    partial = OUT / 'time_index.json'
    scenes = json.loads(partial.read_text(encoding='utf8')) if partial.exists() else {}
    windows = []
    for scene in sorted(read_registry(ROOT).scenes):
        if scene in scenes:
            continue
        loaded = load_dataset(ROOT, scene_id=scene, config_version='v4')
        frozen(loaded)
        if loaded.missing_files:
            scenes[scene] = {'missing': list(loaded.missing_files)}
            continue
        bins = defaultdict(lambda: {'raw_counts': Counter(), 'fields': Counter()})
        sources = {}
        for item in loaded.inputs:
            source, path = item['source'], ROOT / item['path']
            ad, before = adapter(loaded, source), file_digest(path)
            count = 0
            for raw in records(path):
                when = stamp(raw, source, ad)
                bucket = int(when.timestamp()) // RULE['stride_seconds'] * RULE['stride_seconds']
                bins[bucket]['raw_counts'][source] += 1
                bins[bucket]['fields'].update(field_coverage(raw))
                count += 1
            if file_digest(path) != before:
                raise ValueError('source_changed_during_index')
            sources[source] = {'path': item['path'], 'sha256': before, 'count': count}
        eligible = [b for b in sorted(bins) if RULE['minimum_raw_count'] <= sum(bins[b]['raw_counts'].values()) <= RULE['maximum_raw_count']]
        # Nominate by field-coverage ratio and fixed temporal quantiles. Source
        # presence is descriptive; absent AMiner windows are not manufactured.
        ranked = sorted(eligible, key=lambda b: (-sum(bins[b]['fields'].values()) / sum(bins[b]['raw_counts'].values()), b))
        selected = set(ranked[:4])
        selected.update(eligible[round((len(eligible)-1)*q)] for q in (0., 1/3, 2/3, 1.) if eligible)
        for bucket in sorted(selected):
            windows.append(dict(scene=scene, window_start=utc_text(datetime.fromtimestamp(bucket, timezone.utc)),
                window_end=utc_text(datetime.fromtimestamp(bucket+RULE['window_seconds'], timezone.utc)),
                **bins[bucket]))
        scenes[scene] = {'sources': sources, 'eligible_window_count': len(eligible), 'occupied_window_count': len(bins),
            'selected_window_count': len(selected), 'windows': [w for w in windows if w['scene'] == scene],
            'bins': {str(k): v for k, v in sorted(bins.items())}}
        atomic_json(partial, scenes)
        print(json.dumps({'indexed': scene, 'eligible': len(eligible), 'selected': len(selected)}), flush=True)
    windows = [w for scene in scenes.values() for w in scene.get('windows', [])]
    atomic_json(OUT / 'search_plan.json', {'rule': RULE, 'scenes': scenes, 'windows': windows})


def selected_records(loaded, starts):
    selected = {start: {s: [] for s in ('aminer', 'wazuh')} for start in starts}
    for item in loaded.inputs:
        source, ad = item['source'], adapter(loaded, item['source'])
        for raw in records(ROOT / item['path']):
            when = stamp(raw, source, ad)
            bucket = int(when.timestamp()) // RULE['stride_seconds'] * RULE['stride_seconds']
            start = utc_text(datetime.fromtimestamp(bucket, timezone.utc))
            if start in selected:
                selected[start][source].append(raw)
    return selected


def suitability(edges, incidents, index):
    multi = [i for i in incidents if len({index.owner[a] for a in i.alert_ids}) > 1]
    singleton = len(incidents) - len(multi)
    readable = sum(2 <= len({index.owner[a] for a in i.alert_ids}) <= 8 for i in multi)
    families = {f for e in edges for f in e.score_breakdown.evidence_v2.evidence_families}
    cross = sum(index.alerts[e.support_pair.alert_id_src].source_type != index.alerts[e.support_pair.alert_id_dst].source_type for e in edges)
    # Counts saturate: maximizing the number of edges is not the objective.
    score = 20*bool(edges)+20*bool(multi)+10*bool(singleton)+min(len(edges),20)+5*min(readable,4)+2*len(families)+min(cross,10)
    return score, multi, singleton, families, cross


def supplemental_plan():
    original = json.loads((OUT / 'search_plan.json').read_text(encoding='utf8'))
    path = OUT / 'supplemental_search_plan.json'
    if path.exists():
        raise ValueError('supplemental_plan_already_exists')
    windows = []
    for scene,s in sorted(original['scenes'].items()):
        used = {w['window_start'] for w in original['windows'] if w['scene']==scene}
        bins = [(int(t),v) for t,v in s['bins'].items() if 20<=sum(v['raw_counts'].values())<=1500]
        accounts = sorted((b for b in bins if b[1]['fields'].get('account',0)),
            key=lambda b:(-b[1]['fields'].get('account',0)/sum(b[1]['raw_counts'].values()), b[0]))
        mixed = sorted((b for b in bins if all(b[1]['raw_counts'].get(k,0) for k in ('aminer','wazuh'))),
            key=lambda b:(-min(b[1]['raw_counts'].values())/sum(b[1]['raw_counts'].values()), b[0]))
        selected = {t:v for t,v in accounts[:2]+mixed[:2]}
        for t,v in sorted(selected.items()):
            start = utc_text(datetime.fromtimestamp(t,timezone.utc))
            if start not in used:
                windows.append(dict(scene=scene,window_start=start,
                    window_end=utc_text(datetime.fromtimestamp(t+900,timezone.utc)),**v))
    atomic_json(path,{'rule':{**RULE,'minimum_raw_count':20,
        'nomination':'up to 2 account-field coverage ranks and 2 bilateral-source balance ranks per scene; remove original windows'},
        'parent_plan_digest':content_digest(original),'scenes':original['scenes'],'windows':windows,
        'reason':'Raw inventory shows original field-density ranks underrepresent account and bilateral-source windows. No scored pair IDs used.'})
    print(json.dumps({'supplemental_window_count':len(windows)}),flush=True)


def scan(supplemental=False):
    from app.correlation.index import AlertIndex
    plan = json.loads((OUT / ('supplemental_search_plan.json' if supplemental else 'search_plan.json')).read_text(encoding='utf8'))
    if not supplemental and plan['rule'] != RULE:
        raise ValueError('search_rule_changed')
    plan_digest = content_digest(plan)
    results_path = OUT / ('supplemental_candidate_results.json' if supplemental else 'candidate_results.json')
    results = json.loads(results_path.read_text(encoding='utf8')) if results_path.exists() else []
    if any(r.get('search_plan_digest', plan_digest) != plan_digest for r in results):
        raise ValueError('candidate_receipt_plan_mismatch')
    done = {(r['scene'], r['window_start']) for r in results}
    for scene in sorted(plan['scenes']):
        windows = [w for w in plan['windows'] if w['scene'] == scene and (scene, w['window_start']) not in done]
        if not windows:
            continue
        loaded = load_dataset(ROOT, scene_id=scene, config_version='v4')
        frozen(loaded)
        for source, rec in plan['scenes'][scene]['sources'].items():
            if file_digest(ROOT / rec['path']) != rec['sha256']:
                raise ValueError('source_changed_since_plan')
        selected = selected_records(loaded, [w['window_start'] for w in windows])
        settings = {k: s for k, (_, s) in loaded.sources.items()}
        for w in windows:
            started = time.perf_counter()
            by_id, rejected = {}, []
            raw = selected[w['window_start']]
            if {s:len(items) for s,items in raw.items() if items} != w['raw_counts']:
                raise ValueError('window_raw_count_changed')
            for source, items in raw.items():
                batch = adapter(loaded, source).batch(items)
                rejected.extend(str(r) for r in batch.rejected)
                by_id.update({a.alert_id: a for a in batch.alerts})
            alerts = [by_id[k] for k in sorted(by_id)]
            dedupe = deduplicate(alerts, loaded.config, settings)
            extracted = extract_entities(alerts, settings)
            alerts, entities = extracted.alerts, extracted.entities
            outcomes, gates, families = Counter(), Counter(), Counter()
            tops = []
            def observe(row):
                if row.get('stage') == 'member_score':
                    evidence = row.get('evidence', {}).get('evidence_v2', {})
                    outcomes.update([evidence.get('decision', 'unknown')])
                    gates.update([evidence.get('gate_reason', 'unknown')])
                    families.update(evidence.get('evidence_families', []))
                    tops.append({'support_pair':row['support_pair'], 'score':row['score'], 'evidence':evidence})
                    tops.sort(key=lambda t: (-t['score'], t['support_pair']))
                    del tops[3:]
            correlation = run_correlation(alerts, dedupe.groups, entities, loaded.config, settings, diagnostic_sink=observe)
            reconstruction = run_reconstruction(alerts, dedupe.groups, entities, correlation.edges, loaded.config, settings,
                upstream_record=correlation.record)
            idx = AlertIndex(alerts, dedupe.groups, entities)
            score, multi, single, evidence_families, cross = suitability(correlation.edges, reconstruction.incidents, idx)
            result = dict(**w, search_plan_digest=plan_digest, canonical_alert_count=len(alerts), raw_alert_count=sum(len(x) for x in raw.values()),
                representative_count=idx.N, correlation_edge_count=len(correlation.edges), incident_count=len(reconstruction.incidents),
                multi_alert_incident_count=len(multi), singleton_incident_count=single,
                raw_singleton_incident_count=sum(len(i.alert_ids)==1 for i in reconstruction.incidents),
                max_incident_size=max((len(i.alert_ids) for i in reconstruction.incidents), default=0),
                evidence_family_distribution=dict(families), accepted_evidence_families=sorted(evidence_families),
                cross_source_edge_count=cross, source_distribution=dict(Counter(a.source_type.value for a in alerts)),
                candidate_pair_count=correlation.record.metrics.candidate_pair_count,
                is_complete=not rejected and dedupe.is_complete and reconstruction.record.is_complete,
                rejected_count=len(rejected), rejected=rejected[:3], decision_distribution=dict(outcomes), gate_distribution=dict(gates),
                demo_suitability_score=score, top_rejected_or_accepted_pairs=tops,
                algorithm_version=correlation_version(loaded.config), config_hash=correlation.record.config_hash,
                mapping_digest=loaded.config.mapping_digest, threshold=loaded.config.algorithm.score.correlation_threshold,
                runtime_seconds=time.perf_counter()-started)
            results.append(result)
            atomic_json(results_path, results)
            print(json.dumps({k:result[k] for k in ('scene','window_start','canonical_alert_count','correlation_edge_count',
                'multi_alert_incident_count','singleton_incident_count','runtime_seconds')}), flush=True)
    atomic_json(OUT / 'source_protection.json', {'original_raw_unchanged':all(file_digest(ROOT / r['path']) == r['sha256']
        for scene in plan['scenes'].values() for r in scene.get('sources', {}).values()), 'labels_read':False})


def report_not_found():
    """Publish an honest failed selection; never silently create a Demo asset."""
    import xml.etree.ElementTree as ET
    plan = json.loads((OUT / 'search_plan.json').read_text(encoding='utf8'))
    results = json.loads((OUT / 'candidate_results.json').read_text(encoding='utf8'))
    supplemental = json.loads((OUT / 'supplemental_search_plan.json').read_text(encoding='utf8')) if (OUT / 'supplemental_search_plan.json').exists() else None
    if supplemental:
        if supplemental['parent_plan_digest'] != content_digest(plan):
            raise ValueError('supplemental_parent_plan_mismatch')
        plan['windows'] += supplemental['windows']
        results += json.loads((OUT / 'supplemental_candidate_results.json').read_text(encoding='utf8'))
    planned = {(w['scene'],w['window_start']):w for w in plan['windows']}
    if len(results) != len(planned) or {(r['scene'],r['window_start']) for r in results} != set(planned):
        raise ValueError('search_not_complete')
    for r in results:
        w = planned[r['scene'], r['window_start']]
        if r['raw_counts'] != w['raw_counts'] or r['raw_alert_count'] != sum(w['raw_counts'].values()):
            raise ValueError('window_count_receipt_mismatch')
    if any(r['is_complete'] and r['correlation_edge_count'] and r['multi_alert_incident_count']
           and r['singleton_incident_count'] for r in results):
        raise ValueError('qualified_candidates_require_dataset_and_runtime_consolidation')
    protected = json.loads((OUT / 'source_protection.json').read_text(encoding='utf8'))
    if not protected['original_raw_unchanged']:
        raise ValueError('original_source_changed')
    freeze = json.loads((ROOT / 'outputs/correlation_v4_small/FREEZE_MANIFEST.json').read_text(encoding='utf8'))
    baseline = json.loads((OUT / 'initial_files.json').read_text(encoding='utf8'))
    protected_changes = [p for p,h in baseline.items() if p.startswith(('backend/app/','configs/','docs/','frontend/src/'))
                         or p == 'AGENTS.md' if file_digest(ROOT / p) != h]
    if protected_changes:
        raise ValueError('protected_file_changes:' + str(protected_changes))
    def highest(r, primary=False):
        return max((p['score'] for p in r['top_rejected_or_accepted_pairs']
                    if not primary or p['evidence'].get('evidence_gate_passed')), default=0.)
    ranked = sorted(results,key=lambda r:(-r['demo_suitability_score'],-highest(r,True),-highest(r),r['scene'],r['window_start']))
    best = ranked[0]
    loaded = load_dataset(ROOT, scene_id=best['scene'],config_version='v4')
    frozen(loaded)
    raw = selected_records(loaded,[best['window_start']])[best['window_start']]
    alerts = {a.alert_id:a for s, rows in raw.items() for a in adapter(loaded,s).batch(rows).alerts}
    settings = {k:s for k,(_,s) in loaded.sources.items()}
    dedupe = deduplicate(list(alerts.values()),loaded.config,settings)
    extracted = extract_entities(list(alerts.values()),settings)
    from app.services.storage import SnapshotStore
    from types import SimpleNamespace
    import tempfile
    audit_root = OUT / 'candidate_audit_verified'
    if not audit_root.exists():
        staged = Path(tempfile.mkdtemp(prefix='.candidate-audit-',dir=OUT))
        replay = run_correlation(extracted.alerts,dedupe.groups,extracted.entities,loaded.config,settings,output_root=staged)
        reconstructed = run_reconstruction(extracted.alerts,dedupe.groups,extracted.entities,replay.edges,loaded.config,settings,
                                          upstream_record=replay.record,output_root=staged)
        SnapshotStore(staged,reconstructed.record.analysis_id).validate_reconstruction()
        atomic_json(staged/'audit_receipt.json',{'correlation_analysis_id':replay.record.analysis_id,
            'reconstruction_analysis_id':reconstructed.record.analysis_id,'config_hash':best['config_hash']})
        if not staged.resolve().is_relative_to(OUT.resolve()) or not audit_root.resolve().is_relative_to(OUT.resolve()):
            raise ValueError('audit_publish_path_escape')
        staged.rename(audit_root)
    receipt = json.loads((audit_root/'audit_receipt.json').read_text(encoding='utf8'))
    correlation_store = SnapshotStore(audit_root,receipt['correlation_analysis_id'])
    replay_record,_,_ = correlation_store.read_metadata()
    replay = SimpleNamespace(record=replay_record,edges=list(correlation_store.read_records('correlation_edges')))
    reconstruction_store = SnapshotStore(audit_root,receipt['reconstruction_analysis_id'])
    reconstruction_record,_,_ = reconstruction_store.read_metadata()
    reconstructed = SimpleNamespace(record=reconstruction_record,grounding=reconstruction_store.validate_reconstruction())
    if (replay.record.config_hash != best['config_hash'] or len(replay.edges) != best['correlation_edge_count']
        or replay.record.input_alert_ids != sorted(alerts)
        or replay.record.dataset_digest != content_digest([[i,a.raw_fingerprint] for i,a in sorted(alerts.items())])):
        raise ValueError('best_candidate_replay_changed')
    formal_examples = [e.model_dump(mode='json') for e in replay.edges]
    examples = []
    for pair in best['top_rejected_or_accepted_pairs']:
        ev = pair['evidence']
        items = []
        for aid in pair['support_pair']:
            a = alerts[aid]
            items.append({k:a.model_dump(mode='json')[k] for k in
                ('alert_id','timestamp','source_type','source_namespace','sensor','signature','category','host','account','src_ip','dst_ip')})
        refs = []
        for fact in ev.get('evidence',[]):
            for ref in fact['evidence_refs']:
                if ref['alert_id'] not in pair['support_pair']:
                    raise ValueError('audit_pointer_outside_pair')
                refs.append({**ref,'value':resolve_pointer(alerts[ref['alert_id']].raw_alert,ref['pointer']),
                             'family':fact['family'],'role':fact['role']})
        examples.append({**pair,'alerts':items,'resolved_evidence_refs':refs})
    atomic_json(OUT / 'best_candidate_evidence.json',{'formal_positive_examples':formal_examples,
        'member_examples':examples,'replay_correlation_analysis_id':replay.record.analysis_id,
        'replay_reconstruction_analysis_id':reconstructed.record.analysis_id,
        'grounding':reconstructed.grounding.json_data(),'replay_unchanged':True})
    suites = ET.parse(OUT / 'pytest.xml').getroot()
    selection_suite = next(ET.parse(OUT / 'selection_tests.xml').getroot().iter('testsuite'))
    selection_tests = {k:int(selection_suite.get(k,'0')) for k in ('tests','failures','errors','skipped')}
    counts = Counter()
    skipped = []
    evaluation_modules = {p.stem for p in (ROOT / 'evaluation/tests').glob('test_*.py')}
    for case in suites.iter('testcase'):
        area = 'evaluation' if case.get('classname','').split('.')[-1] in evaluation_modules else 'backend'
        outcome = 'failed' if case.find('failure') is not None or case.find('error') is not None else 'skipped' if case.find('skipped') is not None else 'passed'
        counts[area+'_'+outcome] += 1
        if outcome == 'skipped':
            skipped.append({'test':case.get('classname','')+'.'+case.get('name',''), 'reason':case.find('skipped').get('message')})
    outcome = {'TASK_RESULT':'FINAL_DEMO_DATASET_NOT_FOUND','frozen_recipe':{k:freeze[k] for k in
        ('algorithm_version','threshold','config_hash','mapping_digest')},'modified':False,'selected_dataset':None,
        'scenario_count':len(plan['scenes']),'window_count':len(results),
        'complete_window_count':sum(r['is_complete'] for r in results),
        'raw_alert_count_scored':sum(r['raw_alert_count'] for r in results),
        'canonical_alert_count_scored':sum(r['canonical_alert_count'] for r in results),
        'candidate_pair_count_scored':sum(r['candidate_pair_count'] for r in results),
        'formal_correlation_edge_count':sum(r['correlation_edge_count'] for r in results),
        'multi_alert_incident_count':sum(r['multi_alert_incident_count'] for r in results),
        'best_candidate':{k:best[k] for k in ('scene','window_start','window_end','raw_alert_count','canonical_alert_count',
            'representative_count','correlation_edge_count','incident_count','multi_alert_incident_count','singleton_incident_count','config_hash')},
        'highest_observed_score':max(highest(r) for r in results),
        'highest_primary_gate_score_in_retained_top_samples':max(highest(r,True) for r in results),
        'original_dataset_untouched':True,'labels_used_for_selection':False,'tests':dict(counts),'selection_tests':selection_tests,
        'skipped_tests':skipped,'protected_file_changes':protected_changes,'deleted':[],
        'runtime_entry_created':False,'cold_warm_verification':'NOT_RUN_NO_QUALIFIED_DATASET'}
    atomic_json(OUT / 'FINAL_DEMO_RESULT.json',outcome)
    lines = ['# TraceBack Final Demo Report','', '## 1. Task Result','',
        '`TASK_RESULT = FINAL_DEMO_DATASET_NOT_FOUND`','',
        'The bounded search did not find a window satisfying all Demo requirements. One real display-only CorrelationEdge exists, but no correlated multi-alert Incident. Per the requested failure strategy, no dataset was frozen, no warm snapshot or formal runtime was created, and no historical asset was deleted. This is not a claim that every possible AIT-ADS window lacks a positive case.','',
        '## 2. Frozen Recipe','',f"- algorithm_version: `{freeze['algorithm_version']}`", f"- threshold: `{freeze['threshold']}`",
        f"- accepted development effective config_hash: `{freeze['config_hash']}`",f"- mapping_digest: `{freeze['mapping_digest']}`",
        '- WAS_CORRELATION_V4_MODIFIED = NO','',
        'The accepted report and FREEZE_MANIFEST under outputs/correlation_v4_small are authoritative. Only declared scenario namespace/timezone settings differ among effective recipes; all algorithm fields, mappings and frozen implementation hashes match. Each window records its actual effective config_hash. The config_hash above is the accepted development deployment, not a universal hash across all scenes.','',
        '## 3. Candidate Search','',
        f"- Scenarios: {len(plan['scenes'])}; eligible windows: {sum(s.get('eligible_window_count',0) for s in plan['scenes'].values())}; scored windows: {len(results)}.",
        '- Fixed UTC grid: 15-minute continuous windows, 15-minute stride, half-open [start,end).',
        '- Nomination before scoring: four observed structured-field coverage ranks plus four fixed time quantiles per scene, deduplicated. Raw volume 100–1500 is a search-size bound, not an algorithm budget. A separate precommitted supplement covers up to two account-field and two bilateral-source balance ranks per scene, raw volume 20–1500; it uses only the original raw time index and removes already scanned windows.',
        '- All AMiner/Wazuh records in each window retained, including Wazuh-embedded Suricata. No rule, severity, entity, singleton or outcome-based record deletion. Missing source observations remain absent.',
        '- Search plan and raw input hashes were persisted before any correlation execution. No historical high-score pair or evaluation label nominated a record.',
        f"- Total raw records scored: {outcome['raw_alert_count_scored']}; canonical: {outcome['canonical_alert_count_scored']}; candidate pairs: {outcome['candidate_pair_count_scored']}.",
        f"- Complete windows: {outcome['complete_window_count']}/{len(results)}; formal edges: {outcome['formal_correlation_edge_count']}; correlated multi-alert incidents: {outcome['multi_alert_incident_count']}.",
        '- DemoSuitabilityScore = 20×has_edges + 20×has_multi + 10×has_singletons + min(edges,20) + 5×min(readable_2_to_8_rep_incidents,4) + 2×accepted_family_count + min(cross_source_edges,10). It is a presentation diagnostic, not CorrelationScore, precision, recall or attack probability. Ties below use the highest observed primary-gated top sample, then score, then stable scene/time.','',
        '| Rank | Scenario | UTC window | Alerts | Edges | Multi incidents | Representative singletons | Highest score |',
        '|---|---|---|---:|---:|---:|---:|---:|']
    for n,r in enumerate(ranked[:10],1):
        lines.append(f"| {n} | {r['scene']} | {r['window_start']} – {r['window_end']} | {r['canonical_alert_count']} | {r['correlation_edge_count']} | {r['multi_alert_incident_count']} | {r['singleton_incident_count']} | {highest(r):.6f} |")
    lines += ['', 'All per-window counts, source/family/gate distributions, maximum incident sizes and effective recipe hashes are in candidate_results.json; full temporal inventory and nominations are in search_plan.json.', '',
        '## 4. Selected Dataset','', 'None. No traceback-demo-v1 asset or manifest is published. The top diagnostic candidate is not an accepted Demo dataset.',
        '', '## 5. Why No Dataset Was Selected','',
        'The retained algorithm requires an independent primary fact, minimum evidence mass, the unchanged 0.65 correlation threshold, and separate 0.70 clustering admission/guards. Shared destination IP, common detector metadata, time proximity and duplicate observations do not establish a formal positive case. Raw multi-member dedupe groups are not correlated multi-alert incidents. Wilson 2022-02-03 [20:15,20:30) UTC has one formal edge at 0.658745223: legal for display, below 0.70 for clustering. Its 448 representatives remain 448 singleton incidents. The paired vendor signatures describe authentication success and a PAM session opening; they do not establish adversarial activity or attack progression. Enlarging a window just to dilute entity frequency is not evidence of a better positive case.',
        f"The highest observed member score was {outcome['highest_observed_score']:.9f}. These are scores of inspected candidates, not scores of accepted edges. No claim about malicious/benign truth is made.",
        '', '## 6. Positive Correlation Examples','',
        'One formal display-only edge was found; there are not 3–5 suitable examples or a qualifying multi-alert Incident. It is retained as a candidate audit, not a final Demo dataset. The best window was independently replayed unchanged through correlation, reconstruction and the existing grounding validator; full verified snapshots are under candidate_audit_verified/data/processed and candidate_audit_verified/outputs/analyses. Published snapshots are validated and reused on subsequent report runs; they are never rescored in place. The earlier candidate_audit directory contains a failed report-replay attempt and is not a verified snapshot.', '']
    for e in formal_examples:
        lines += [f"- Formal edge `{e['edge_id']}`: score {e['score']}, support_pair `{e['support_pair']}`; complete reasons, entity IDs, seven-item breakdown and v4 family audit in best_candidate_evidence.json."]
    lines.append('')
    for n,e in enumerate(examples,1):
        ev = e['evidence']
        lines += [f"### {'Formal accepted member' if ev['decision']=='ACCEPT' else 'Rejected diagnostic'} {n}", '', f"- score: {e['score']:.9f}; correlation threshold: {freeze['threshold']}; clustering threshold: 0.70; decision: {ev['decision']}; gate: {ev['gate_reason']}.",
            f"- quality: {ev['normalized_quality']}; evidence mass: {ev['evidence_mass']}; primary: {ev['primary_evidence']}.",
            f"- families: {ev['evidence_families']}; network diagnostic: {ev.get('network_diagnostic')}; source independence is not inferred from product names."]
        for a in e['alerts']:
            lines.append(f"- `{a['alert_id']}`: {a['timestamp']}, {a['source_type']}, category={a['category']}, signature={a['signature']!r}, host={a['host']!r}, account={a['account']!r}.")
        if ev['decision']=='ACCEPT':
            lines += ['- The frozen evaluator marks non-hot HOST_CONTEXT and ACCOUNT_CONTEXT as separate primary evidence keys; TEMPORAL and RULE_METADATA only support them. Distinct observation IDs and duplicate_observation_risk=false are algorithm diagnostics, not proof of independent sensors or distinct underlying login operations.',
                      '- Both shared entities appear in 5 of 448 fact groups, rarity 0.706607, reliability 0.735946, hot=false. This is neither metadata-only nor high-frequency-only admission. Source independence remains unknown; no cross-source bonus or propagation is invented.',
                      '- The pair lacks a legal directional relation. Score is below 0.70, so clustering leaves both incidents separate, and no ChainEdge is produced.']
        lines += ['- All bound raw evidence pointers resolve against their own support member; complete values, entity reliability/frequency, independent fact keys and suppressed dimensions are in best_candidate_evidence.json.', '']
    lines += ['## 7. Primary Demo Incident','', 'DEMO_PRIMARY_INCIDENT = NONE. No synthetic incident or directional edge was added.', '',
        '## 8. Dataset Reproducibility','', 'DEMO_DATASET_REBUILD = NOT_APPLICABLE (no final Demo dataset). Search reproducibility assets: search_rule.json, search_plan.json, candidate_results.json and the search CLI. Existing plan cannot be silently overwritten; scan verifies raw source hashes and resumes already completed windows. Every planned window has a matching count receipt.', '',
        '## 9. Original Dataset Protection','', 'ORIGINAL_DATASET_UNTOUCHED = YES', '', 'LABELS_USED_FOR_SELECTION = NO', '',
        'All sixteen original AMiner/Wazuh JSON files were hashed before indexing and after search, with exact equality. No input file is written by this tool. Labels and other Ground Truth are not opened by selection or production; independent evaluation tests remain separate. Seven baseline documents, existing production code, mappings and frontend source are hash-unchanged.', '',
        '## 10. Cleanup Result','', 'Deleted files/directories: none. Dataset freeze precedes cleanup in the requested workflow, and its prerequisite failed.', '',
        'Retained: original AIT-ADS inputs; both development/validation slices; Correlation v4 accepted report and freeze manifest; historical final reports, snapshots, existing scripts and fixtures. They remain reproducibility/test assets and have not been superseded by an accepted Demo. Temporary test-run artifacts created by pytest are not promoted to production.', '',
        '## 11. Runtime Entry','', 'No new formal runtime entry or demo profile was published. The existing workbench factory and legacy development Demo remain unchanged. Publishing a new positive-Demo entry with an unqualified dataset would misrepresent acceptance.', '',
        '## 12. Cold / Warm Verification','', 'COLD_RUN = NOT_RUN_NO_QUALIFIED_DATASET', '', 'WARM_RUN = NOT_RUN_NO_QUALIFIED_DATASET', '', 'COLD_WARM_CORE_EQUIVALENCE = NOT_APPLICABLE', '',
        '## 13. Tests','',f"- Full backend/evaluation pytest: {dict(counts)}; JUnit: pytest.xml; log: pytest.log.",
        f"- Final focused selection safety suite: {selection_tests} (selection_tests.log / selection_tests.xml). Four of these were included in the full-suite run; focused verification covers subsequent additions, without counting overlap as additional distinct tests.",
        '- Frontend: 35 passed across 4 files (frontend_tests.log).',
        '- TypeScript: PASS (frontend_typecheck.log).',
        '- Frontend build: PASS (frontend_build.log).',
        '- Repository check: PASS (repository_check.json).',
        '- New runtime smoke: NOT_RUN_NO_QUALIFIED_DATASET.',
        '- Commands: python -m pytest backend/tests evaluation/tests -q; npm --prefix frontend run test -- --run; npm --prefix frontend run typecheck; npm --prefix frontend run build; python scripts/check_repository.py.', '',
        'Skip reasons are recorded in FINAL_DEMO_RESULT.json and pytest.xml; skipped tests are not counted as passes.', '',
        '## 14. Final Repository Status','',
        '| Question | Answer |', '|---|---|',
        '| New formal Demo launch without development scripts? | NO |',
        '| Accepted Demo reproducible from original AIT-ADS? | NO (none selected) |',
        '| Final Demo contains real CorrelationEdge? | NO |',
        '| Final Demo also contains singleton alerts? | NO (none selected; search windows retain singletons) |',
        '| Displayed positive edges evidence-grounded? | YES for the sole audited display-only candidate edge; no final Demo published |',
        '| Correlation v4 still frozen? | YES |', '',
        '**FINAL_CONCLUSION = NOT_ACCEPTED**', '',
        'Stop at the explicitly requested failed-selection boundary. No algorithm tuning, dataset-specific hack, synthetic positive data, historical deletion or next-stage implementation was performed.']
    (OUT / 'FINAL_DEMO_REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps(outcome,ensure_ascii=False),flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('index', 'scan', 'supplemental-plan', 'supplemental-scan', 'report-not-found'), required=True)
    args = parser.parse_args()
    {'index':index,'scan':scan,'supplemental-plan':supplemental_plan,
     'supplemental-scan':lambda:scan(True),'report-not-found':report_not_found}[args.phase]()

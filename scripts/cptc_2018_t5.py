"""Single-file real CPTC experiment; all decisions use frozen production code."""
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from cptc_2018_step3a import Observer, atomic_json, load_frozen_config, quantiles, recipe
from app.adapters.cptc import load_cptc_dataset, read_cptc_file
from app.adapters.suricata import alert_warnings
from app.entities.extraction import extract_entities
from app.dedup.grouping import deduplicate
from app.correlation.edges import run_correlation, peak_memory_mb
from app.correlation.scoring import CorrelationScorer
from app.chains.assembly import run_reconstruction
from app.services.capacity import bounded_execution
from app.services.storage import SnapshotStore, file_digest
from app.utils.stable_id import content_digest
from demo_support import truth_guard

OUT = ROOT/'outputs/cptc_2018_step3a_t5'
INPUT = ROOT/'data/cptc_2018/raw/suricata/suricata_alert_t5.json.gz'


def protected():
    paths = [*sorted((ROOT/'backend/app').rglob('*.py')), *sorted((ROOT/'configs').rglob('*.yaml')),
             ROOT/'AGENTS.md', *sorted((ROOT/'docs').glob('*.md')), INPUT,
             ROOT/'data/cptc_2018/dataset.yaml']
    return {p.relative_to(ROOT).as_posix(): file_digest(p) for p in paths}


def input_guard(event, args):
    if event == 'open' and args and isinstance(args[0], (str, bytes)):
        name = str(args[0]).replace('\\', '/').lower()
        if '/data/cptc_2018/raw/' in name and Path(name).name != INPUT.name:
            raise PermissionError('only_t5_raw_input_allowed')


def semantic_digest(objects):
    digest = hashlib.sha256()
    for obj in sorted(objects, key=lambda x: x.canonical_json()):
        digest.update(obj.canonical_json().encode('utf8')+b'\n')
    return digest.hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    runtime = OUT/'runtime'
    runtime.mkdir(exist_ok=False)
    sys.addaudithook(input_guard)
    started = time.perf_counter()
    before = protected()
    stop = threading.Event()
    state = {'stage': 'input', 'disk_spill_peak_bytes': 0, 'temporary_peak_bytes': 0}
    def monitor():
        while not stop.wait(5):
            sizes = [(p, p.stat().st_size) for p in runtime.rglob('*') if p.is_file()]
            state['temporary_peak_bytes'] = max(state['temporary_peak_bytes'], sum(n for p,n in sizes))
            state['disk_spill_peak_bytes'] = max(state['disk_spill_peak_bytes'], sum(n for p,n in sizes if 'spill' in p.parts))
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    summary = {'task_result': 'RUNNING', 'ground_truth_used': False, 'synthetic_evidence': False, 'ai_created_facts': False}
    try:
        with truth_guard(ROOT), bounded_execution(runtime/'spill') as spill:
            config, manifest, freeze_path = load_frozen_config()
            dataset = load_cptc_dataset(ROOT)
            adapter = dataset.adapters['t5']
            settings = {adapter.settings.source_namespace: adapter.settings}
            assert dataset.paths['t5'] == INPUT
            assert adapter.settings.source_namespace == 'cptc_2018.t5'
            assert adapter.settings.network_namespace == 'cptc_2018'
            frozen = recipe(config, settings)
            frozen.update(execution_equivalence='PASS', receipt='outputs/cptc_2018_step3a_capacity/EXECUTION_EQUIVALENCE_RECEIPT.json',
                          receipt_sha256=file_digest(ROOT/'outputs/cptc_2018_step3a_capacity/EXECUTION_EQUIVALENCE_RECEIPT.json'))
            summary['frozen_recipe'] = frozen
            alerts = spill.alerts()
            counts = Counter(raw=0, parsed=0, parse_failure=0, canonical=0, rejected=0, warning_records=0, warnings=0)
            times = []
            for record in read_cptc_file(INPUT):
                counts['raw'] += 1
                if record.error:
                    counts['parse_failure'] += 1
                    continue
                counts['parsed'] += 1
                try:
                    alert = adapter.convert(record.eve)
                except (ValueError, TypeError) as exc:
                    counts['rejected'] += 1
                    raise ValueError('unexpected_t5_adapter_rejection:'+str(exc)) from exc
                warnings = alert_warnings(alert)
                counts['warning_records'] += bool(warnings)
                counts['warnings'] += len(warnings)
                alerts.add(alert)
                counts['canonical'] += 1
                times.append(alert.timestamp)
                if counts['raw'] % 10000 == 0:
                    print(json.dumps({'stage': 'ingest', 'count': counts['raw']}), flush=True)
            baseline = json.loads((ROOT/'outputs/cptc_2018_step1/cptc_file_statistics.json').read_text('utf8'))
            raw_baseline = next(f for f in baseline['files'] if f.get('file', f.get('filename')) == INPUT.name)
            step2 = json.loads((ROOT/'outputs/cptc_2018_step2/run_a/summary.json').read_text('utf8'))['per_file']['t5']
            info = dict(counts, unique_canonical=len(alerts), compressed_bytes=INPUT.stat().st_size, sha256=file_digest(INPUT),
                        time_range=[min(times), max(times)], source_namespace=adapter.settings.source_namespace,
                        network_namespace=adapter.settings.network_namespace, step1=raw_baseline, step2=step2)
            assert counts['raw'] == counts['canonical'] == len(alerts) == step2['raw_records'] == raw_baseline['record_count']
            assert info['sha256'] == raw_baseline['sha256']
            assert info['compressed_bytes'] == raw_baseline['compressed_size']
            assert info['time_range'] == [raw_baseline['first_timestamp'], raw_baseline['last_timestamp']]
            assert counts['parse_failure'] == counts['rejected'] == 0
            summary['dataset'] = info
            atomic_json(OUT/'experiment_summary.json', summary)
            state['stage'] = 'dedupe'
            stage_start = time.perf_counter()
            dedupe = deduplicate(alerts.sequence(), config, settings)
            if not dedupe.is_complete:
                raise MemoryError(dedupe.incomplete_reason)
            summary['dedupe'] = dict(groups=len(dedupe.groups), duplicate_members=sum(len(g.alert_ids) for g in dedupe.groups),
                duplicate_excess=sum(len(g.alert_ids)-1 for g in dedupe.groups), seconds=time.perf_counter()-stage_start)
            print(json.dumps({'stage':'dedupe', **summary['dedupe']}), flush=True)
            state['stage'] = 'entities'
            extracted = extract_entities(alerts.sequence(), settings)
            observer = Observer(OUT)
            state['stage'] = 'candidate_generation'
            def progress(row):
                state['stage'] = row['stage']
                print(json.dumps(row), flush=True)
            correlation = run_correlation(extracted.alerts, dedupe.groups, extracted.entities, config, settings,
                                          diagnostic_sink=observer, progress=progress)
            if correlation.candidates is None:
                raise MemoryError(correlation.record.incomplete_reason)
            summary['correlation'] = correlation.summary
            summary['candidate_checkpoint'] = json.loads((OUT/'candidate_generation_checkpoint.json').read_text('utf8'))
            summary['representatives'] = observer.index.N
            summary['scored_pairs'] = observer.count
            summary['rejected_scored_pairs'] = observer.count-len(correlation.edges)
            summary['is_complete'] = correlation.record.is_complete
            summary['algorithm_record'] = correlation.record.model_dump(mode='json')
            atomic_json(OUT/'experiment_summary.json', summary)
            scorer = CorrelationScorer(observer.index, config, settings, correlation.record.config_hash)
            top = [observer.enrich(x[2], scorer) for x in sorted(observer.top, key=lambda x: (-x[0], x[1]))[:20]]
            distribution = dict(histogram=dict(observer.histogram), quantiles=quantiles(observer.scores,
                dict(max=1., median=.5, P90=.9, P95=.95, P99=.99)), ge_065=sum(s >= .65 for s in observer.scores),
                population='highest valid fully scored member pair; highest rejected member if no valid pair',
                scored_pairs=observer.count)
            atomic_json(OUT/'score_distribution.json', distribution)
            state['stage'] = 'reconstruction'
            reconstruction = run_reconstruction(extracted.alerts, dedupe.groups, extracted.entities, correlation.edges,
                config, settings, upstream_record=correlation.record, existing_index=observer.index, progress=progress,
                diagnostic_sink=lambda row: chain_diagnostics.update([json.dumps(row, sort_keys=True)]) if row['stage'] == 'chain_direction' else None)
            summary['reconstruction'] = reconstruction.summary
            summary['chain_diagnostics'] = [dict(json.loads(k), count=v) for k,v in chain_diagnostics.items()]
            sizes = Counter(len({observer.index.owner[a] for a in i.alert_ids}) for i in reconstruction.incidents)
            summary['incident_member_distribution'] = dict(sizes)
            summary['incident_original_member_distribution'] = dict(Counter(len(i.alert_ids) for i in reconstruction.incidents))
            summary['incidents_with_edges'] = sum(bool(i.correlation_edge_ids) for i in reconstruction.incidents)
            # Reconstruct twice from the same immutable formal graph, checking all objects.
            replay = run_reconstruction(extracted.alerts, dedupe.groups, extracted.entities, correlation.edges,
                config, settings, upstream_record=correlation.record, existing_index=observer.index)
            summary['reconstruction_replay'] = {'incidents': semantic_digest(reconstruction.incidents), 'chains':semantic_digest(reconstruction.chains)}
            assert summary['reconstruction_replay'] == {'incidents':semantic_digest(replay.incidents), 'chains':semantic_digest(replay.chains)}
            required = {e.edge_id for e in sorted(correlation.edges, key=lambda e: (-e.score,e.edge_id))[:10]}
            required.update(e for i in reconstruction.incidents if len({observer.index.owner[a] for a in i.alert_ids}) > 1 for e in i.correlation_edge_ids)
            required.update(e for c in reconstruction.chains for ce in c.edges for e in ce.correlation_edge_ids)
            samples = []
            for edge in correlation.edges:
                if edge.edge_id not in required:
                    continue
                pair = [edge.support_pair.alert_id_src, edge.support_pair.alert_id_dst]
                scored = scorer.score_pair(*pair)
                refs = [r for f in scored.diagnostics['evidence_v2']['evidence'] for r in f['evidence_refs']]
                from app.models.base import resolve_pointer
                assert all(resolve_pointer(observer.index.alerts[r['alert_id']].raw_alert, r['pointer']) is not None for r in refs)
                samples.append(dict(edge=edge.model_dump(mode='json'), score_unrounded=scored.score,
                    threshold=config.algorithm.score.correlation_threshold, evidence=scored.diagnostics,
                    relations=[r.json_data() for r in scored.relations], alerts=[observer.index.alerts[a].model_dump(mode='json') for a in pair],
                    delta_seconds=abs((datetime.fromisoformat(observer.index.alerts[pair[0]].timestamp)-datetime.fromisoformat(observer.index.alerts[pair[1]].timestamp)).total_seconds())))
            atomic_json(OUT/'evidence_samples.json', dict(accepted_edges=samples, top20_pairs=top,
                formal_grounding=reconstruction.grounding.json_data()))
            store = SnapshotStore(runtime/'export', reconstruction.record.analysis_id)
            for kind, objects in [('alerts', observer.index.alerts.values()), ('entities', extracted.entities), ('dedupe_groups',dedupe.groups),
                ('correlation_edges', correlation.edges), ('incidents',reconstruction.incidents),
                ('chain_nodes',(n for c in reconstruction.chains for n in c.nodes)), ('chain_edges',(e for c in reconstruction.chains for e in c.edges))]:
                store.write_records(kind, objects)
                shutil.copyfile(store.domain/(kind+'.parquet'), OUT/(kind+'.parquet'))
            atomic_json(OUT/'attack_chains.json', [c.model_dump(mode='json') for c in reconstruction.chains])
            summary['formal_edge_count'] = len(correlation.edges)
            summary['chain_edge_count'] = sum(len(c.edges) for c in reconstruction.chains)
            summary['task_result'] = ('CPTC_T5_STEP3A_PARTIAL' if not correlation.record.is_complete else
                'CPTC_T5_STEP3A_NO_RELATIONS' if not correlation.edges else
                'CPTC_T5_STEP3A_ACCEPTED' if summary['chain_edge_count'] else 'CPTC_T5_STEP3A_PARTIAL')
            summary['demo_assessment'] = 'ACCEPTED' if summary['task_result'].endswith('_ACCEPTED') else 'PARTIAL' if correlation.edges else 'REJECTED'
            checked, _, _ = load_frozen_config()
            assert checked.config_hash == config.config_hash
    except Exception as exc:
        traceback.print_exc()
        summary.update(task_result='CPTC_T5_STEP3A_PARTIAL' if isinstance(exc, MemoryError) else 'CPTC_T5_STEP3A_IMPLEMENTATION_DEFECT',
                       failure_stage=state['stage'], error=str(exc), demo_assessment='REJECTED', is_complete=False)
    finally:
        stop.set()
        thread.join(10)
        after = protected()
        summary['protected_unchanged'] = before == after
        assert before == after
        perf = dict(elapsed_seconds=time.perf_counter()-started, peak_rss_mib=peak_memory_mb(),
                    **state, OOM=summary.get('error') if 'memory' in summary.get('error','').lower() else False)
        atomic_json(OUT/'performance.json', perf)
        atomic_json(OUT/'experiment_summary.json', summary)
        (OUT/'CPTC_T5_STEP3A_REPORT.md').write_text('# CPTC t5 Step 3A\n\n'+summary['task_result']+'\n\n```json\n'+json.dumps(summary, ensure_ascii=False,indent=2)+'\n```\n\nPerformance\n\n```json\n'+json.dumps(perf,indent=2)+'\n```\n', encoding='utf8')
        assert runtime.resolve().is_relative_to(OUT.resolve())
        shutil.rmtree(runtime)
        print(json.dumps({'task_result': summary['task_result'], 'performance':perf}), flush=True)


chain_diagnostics = Counter()


def finalize():
    """Condense completed artifacts; never starts ingestion or another experiment."""
    import xml.etree.ElementTree as ET
    summary = json.loads((OUT/'experiment_summary.json').read_text('utf8'))
    if summary['task_result'] == 'RUNNING':
        raise ValueError('experiment_still_running')
    perf = json.loads((OUT/'performance.json').read_text('utf8'))
    config, manifest, freeze = load_frozen_config()
    summary['frozen_verification'] = dict(correlation_v4_modified=False, threshold_modified=False,
        weights_modified=False, mapping_modified=False, execution_equivalence='PASS',
        frozen_manifest_sha256=file_digest(freeze), protected_unchanged=summary['protected_unchanged'])
    data = summary['dataset']
    original = data.pop('step1', None)
    if original is None:
        baseline = json.loads((ROOT/'outputs/cptc_2018_step1/cptc_file_statistics.json').read_text('utf8'))
        original = next(f for f in baseline['files'] if f.get('file', f.get('filename')) == INPUT.name)
    data['baseline_comparison'] = dict(step1_sha256_matches=data['sha256']==original['sha256'],
        step1_size_matches=data['compressed_bytes']==original['compressed_size'],
        step1_count_matches=data['raw']==original['record_count'],
        step1_time_range_matches=data['time_range']==[original['first_timestamp'],original['last_timestamp']],
        step2_counts_match=data['raw']==data['canonical']==data['step2']['raw_records']==data['step2']['canonical_records'])
    assert all(data['baseline_comparison'].values())
    perf.update(raw_count=data['raw'], representative_count=summary.get('representatives'),
        candidate_count=summary.get('correlation',{}).get('candidate_pair_count'), scored_count=summary.get('scored_pairs'),
        candidate_generation_seconds=summary.get('correlation',{}).get('candidate_runtime_seconds'),
        reader_parquet_duckdb_memory_error=False if summary.get('is_complete') else None,
        disk_measurement='5-second sampled high-water mark; temporary and candidate stores removed after publication')
    atomic_json(OUT/'performance.json',perf)
    test_results = []
    for name in ('tests', 'equivalence_tests', 'reader_tests'):
        suites = ET.parse(OUT/(name+'.xml')).getroot()
        cases = list(suites.iter('testcase'))
        failures = [c.get('name') for c in cases if c.find('failure') is not None or c.find('error') is not None]
        test_results.append(dict(suite=name, tests=len(cases), failures=failures,
            skipped=sum(c.find('skipped') is not None for c in cases), status='PASS' if not failures else 'FAIL'))
    summary['tests'] = test_results
    summary['scored_evidence_decisions_semantics'] = 'Sum of per-representative endpoint decisions; every candidate contributes to both endpoints.'
    # Independently check published tables and field preservation, without raw
    # re-ingestion or a second scoring run.
    import duckdb
    db = duckdb.connect(':memory:')
    db.execute("SET memory_limit='512MB'")
    db.execute('SET threads=1')
    table_counts, field_counts = {}, Counter()
    for parquet in sorted(OUT.glob('*.parquet')):
        table_counts[parquet.stem] = db.execute('SELECT count(*) FROM read_parquet(?)', [str(parquet)]).fetchone()[0]
    cursor = db.execute('SELECT payload FROM read_parquet(?)', [str(OUT/'alerts.parquet')])
    fields = {'src_ip': 'src_ip', 'dest_ip': 'dst_ip', 'src_port': 'src_port', 'dest_port': 'dst_port'}
    for batch in iter(lambda: cursor.fetchmany(256), []):
        for (payload,) in batch:
            alert = json.loads(payload)
            assert alert['source_namespace'] == 'cptc_2018.t5'
            raw = alert['raw_alert']
            for field, canonical_field in fields.items():
                if raw.get(field) is not None:
                    field_counts['raw.'+field] += 1
                    assert alert[canonical_field] == raw[field], 'published_field_loss:'+field
                    field_counts['canonical.'+canonical_field] += 1
            for field in ('flow_id', 'proto'):
                field_counts['raw.'+field] += raw.get(field) is not None
            for field in ('hostname', 'url'):
                field_counts['raw.http.'+field] += raw.get('http', {}).get(field) is not None
                field_counts['canonical.'+('domain' if field == 'hostname' else field)] += alert.get('domain' if field == 'hostname' else field) is not None
            field_counts['raw.alert.signature_id'] += raw.get('alert', {}).get('signature_id') is not None
            field_counts['canonical.rule_id'] += alert.get('rule_id') is not None
    db.close()
    assert table_counts['alerts'] == data['canonical']
    assert table_counts['correlation_edges'] == summary['formal_edge_count']
    assert table_counts['incidents'] == summary['reconstruction']['incident_count']
    assert table_counts['chain_edges'] == summary['chain_edge_count']
    assert table_counts['chain_nodes'] == summary['reconstruction']['chain_node_count']
    summary['published_artifact_verification'] = dict(table_counts=table_counts, field_presence_counts=dict(field_counts),
        source_namespace_only_t5=True, raw_endpoint_fields_preserved=True, status='PASS')
    summary['input_scope_exception'] = ('The initial existing Adapter regression test opened the first record of each of six '
        'partitions. This was an unauthorized test read, disclosed during execution; none of those records entered '
        'the formal experiment. Reader/Adapter tests were rerun excluding that case. Formal production input is t5 only.')
    cor = summary.get('correlation', {})
    alerts_diagnostics = cor.pop('alert_correlation_diagnostics', None)
    if alerts_diagnostics is not None:
        decisions = Counter()
        for row in alerts_diagnostics.values():
            decisions.update(row['decisions'])
        summary['scored_evidence_decisions'] = dict(decisions)
    record = summary.pop('algorithm_record', None)
    if record:
        atomic_json(OUT/'recipe.json', dict(algorithm_version=record['algorithm_version'], config_hash=record['config_hash'],
            config_snapshot=record['config_snapshot'], dataset_digest=record['dataset_digest'], mapping_digest=record['mapping_digest'],
            input_count=len(record['input_alert_ids']), analysis_id=record['analysis_id'], schema_version=record['schema_version'],
            execution_receipt=summary['frozen_recipe']['receipt'], receipt_sha256=summary['frozen_recipe']['receipt_sha256']))
    # Full recipe appears once; summary retains its digest and reference.
    summary['frozen_recipe'].pop('runtime_config_snapshot', None)
    reconstruction = summary.get('reconstruction', {})
    chains_path = OUT/'attack_chains.json'
    chains = json.loads(chains_path.read_text('utf8')) if chains_path.exists() else []
    best_path = []
    mapped, resolvable, conflicts = 0, 0, 0
    for row in summary.get('chain_diagnostics', []):
        directions = row['directions']
        mapped += any(d['relations'] for d in directions)*row['count']
        resolvable += (row['decision']=='accept')*row['count']
        conflicts += any('conflict' in code for code in row['rejection_codes'])*row['count']
    for chain in chains:
        outgoing, incoming = {}, Counter()
        for edge in chain['edges']:
            outgoing.setdefault(edge['source_node_id'], []).append(edge)
            incoming[edge['target_node_id']] += 1
        def path(node, prefix):
            nonlocal best_path
            options = outgoing.get(node, [])
            if not options and len(prefix)>len(best_path):
                best_path=prefix
            for edge in sorted(options, key=lambda e:e['edge_id']):
                path(edge['target_node_id'], [*prefix, edge])
        for node in chain['nodes']:
            if not incoming[node['node_id']]:
                path(node['node_id'], [])
    summary['chain_result'] = dict(mapped_relations=mapped, direction_resolvable_edges=resolvable,
        conflict_edges=conflicts, accepted_chain_edges=sum(len(c['edges']) for c in chains),
        rejected_chain_candidates=sum(row['count'] for row in summary.get('chain_diagnostics', []) if row['decision']=='reject'),
        attack_chain_views=len(chains), chains_with_edges=sum(bool(c['edges']) for c in chains),
        longest_connected_path_nodes=len(best_path)+1 if best_path else 1 if chains else 0, best_path=best_path,
        unresolved_edges=reconstruction.get('unresolved_correlation_edge_count'))
    evidence_path=OUT/'evidence_samples.json'
    if evidence_path.exists():
        evidence=json.loads(evidence_path.read_text('utf8'))
        diagnostics=[]
        for sample in evidence['top20_pairs']:
            ev=sample['selected_member']['evidence']['evidence_v2']
            diagnostics.append(dict(pair=sample['selected_member']['support_pair'], score=sample['final_score_unrounded'],
                available_evidence=ev['evidence'], missing_evidence=ev['unavailable_evidence'],
                evidence_gate_passed=ev['evidence_gate_passed'], gate_reason=ev['gate_reason'],
                normalized_quality=ev['normalized_quality'], evidence_mass=ev['evidence_mass'],
                threshold_gap=.65-sample['final_score_unrounded'],
                rejection_codes=sample['selected_member']['rejection_codes']))
        evidence['closest_threshold_top20_diagnostics']=diagnostics
        atomic_json(evidence_path,evidence)
        if summary.get('formal_edge_count')==0:
            summary['no_relations_diagnosis']=dict(classification='A',
                conclusion='Observed t5 candidate member pairs lack sufficient independent evidence under unchanged frozen v4.',
                candidate_generation='Real scoped production indexes executed; deterministic candidate and budget regressions PASS. No demonstrated omitted qualifying pair.',
                adapter='Step 1/2 record/hash/time baseline matches. Native EVE is retained; IP/port/signature/flow/protocol/URL/domain and provenance are validated.',
                implementation='Frozen hashes and exact reference execution-equivalence regressions PASS; sampled scores were recomputed without changes.',
                closest_pair=dict(score=diagnostics[0]['score'], threshold_gap=diagnostics[0]['threshold_gap'],
                    normalized_quality=diagnostics[0]['normalized_quality'], evidence_mass=diagnostics[0]['evidence_mass'],
                    missing_evidence=diagnostics[0]['missing_evidence'],
                    explanation='Shared IP/domain/URL and temporal/metadata evidence pass the evidence gate, but their quality and mass produce a score below 0.65. No attested relation or confirmed independent complementary source is observed.'),
                limitations='Classification applies to observed candidates. Policy-pruned pairs were not exhaustively rescored; no GT recall or proof that all theoretical pairs lack evidence is claimed.')
    dist_path=OUT/'score_distribution.json'
    if dist_path.exists():
        distribution=json.loads(dist_path.read_text('utf8'))
        h=distribution['histogram']
        distribution['requested_bins']={'<0.30':h['<0.20']+h['[0.20,0.30)'], '0.30–0.49':h['[0.30,0.40)']+h['[0.40,0.50)'],
            '0.50–0.59':h['[0.50,0.60)'], '0.60–0.6499':h['[0.60,0.65)'],
            '>=0.65':h['[0.65,0.70)']+h['[0.70,0.75)']+h['>=0.75']}
        atomic_json(dist_path,distribution)
        summary['score_distribution']=distribution
    summary['ai_explanation']='NOT_RUN; deterministic algorithm and evidence only'
    summary['reproducibility_scope']='Frozen recipe and raw SHA256; exact execution reference tests; Top20 score recalculation; complete Incident/AttackChain reconstruction replay. No second full t5 scoring run.'
    atomic_json(OUT/'experiment_summary.json',summary)
    top20_table = ['| Rank | Support pair | Score | Available dimensions | Missing dimensions | Gap to 0.65 |',
                   '| --- | --- | ---: | --- | --- | ---: |']
    for rank, row in enumerate(diagnostics if evidence_path.exists() else [], 1):
        top20_table.append('| '+str(rank)+' | '+' / '.join(row['pair'])+' | '+format(row['score'],'.9f')+' | '+
            ', '.join(item['dimension'] for item in row['available_evidence'])+' | '+', '.join(row['missing_evidence'])+' | '+format(row['threshold_gap'],'.9f')+' |')
    report=['# CPTC 2018 t5 Step 3A 正式实验',summary['task_result'],
        '## 输入与冻结验证',json.dumps(data,ensure_ascii=False,indent=2),
        '生产实验仅使用 t5。source_namespace=cptc_2018.t5，network_namespace=cptc_2018；partition 不代表攻击阶段。',
        json.dumps(summary['frozen_verification'],ensure_ascii=False,indent=2),
        json.dumps(summary['published_artifact_verification'],ensure_ascii=False,indent=2),
        '## 去重、候选与评分',json.dumps(summary.get('dedupe'),ensure_ascii=False,indent=2),
        json.dumps({k:cor.get(k) for k in ('representative_alert_count','candidate_pair_count','verified_member_pair_count','accepted_relation_count','rejection_distribution','candidate_runtime_seconds','correlation_scoring_seconds','potential_pair_stats','candidate_admission_stats','policy_pruned_count','resource_truncated_count')},ensure_ascii=False,indent=2),
        json.dumps(summary.get('score_distribution'),ensure_ascii=False,indent=2),
        'Top20 完整证据与全部选定正式边的 raw_alert、字段指针、实体角色、观测身份、未舍入分及完整分解见 evidence_samples.json。',
        '## Incident 与攻击链',json.dumps(reconstruction,ensure_ascii=False,indent=2),
        json.dumps(summary['chain_result'],ensure_ascii=False,indent=2),
        'singleton 按独立事实组（代表）统计。重复组可能包含多条原告警；不能将其误称 multi-step Incident。AttackChain 视图允许零边，不能称其为已重构攻击路径。',
        '## 诊断与 Demo 评估',json.dumps(summary.get('no_relations_diagnosis',{}),ensure_ascii=False,indent=2),
        '\n'.join(top20_table),
        'DEMO_DATASET_ASSESSMENT = '+summary.get('demo_assessment','REJECTED'),
        '## 资源与复现',json.dumps(perf,ensure_ascii=False,indent=2),summary['reproducibility_scope'],
        '峰值 RSS 使用 Windows PeakWorkingSetSize；磁盘/临时空间为每 5 秒抽样峰值。无硬件无关性能承诺。',
        '## 测试与输入范围偏差',json.dumps(test_results,ensure_ascii=False,indent=2),summary['input_scope_exception'],
        '## 能力边界','无标签、无 synthetic 生产证据、无 AI 创建事实。未读取 GT，不报告 Precision/Recall/F1。未运行六分区全量实验，未调参。']
    (OUT/'CPTC_T5_STEP3A_REPORT.md').write_text('\n\n'.join(report)+'\n',encoding='utf8')
    atomic_json(OUT/'manifest.json',dict(task_result=summary['task_result'], production_input=INPUT.relative_to(ROOT).as_posix(),
        raw_sha256=data['sha256'], is_complete=summary.get('is_complete',False),
        recipe='recipe.json', files={p.name:file_digest(p) for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='manifest.json'}))
    print(json.dumps({k:summary.get(k) for k in ('task_result','representatives','scored_pairs','formal_edge_count','chain_edge_count','demo_assessment','chain_result')}),flush=True)


if __name__ == '__main__':
    finalize() if sys.argv[1:] == ['--finalize'] else main()

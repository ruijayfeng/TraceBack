"""Allowlisted, complete member replay; score/direction/graph seals precede labels."""
from collections import Counter
from pathlib import Path
import gzip
import json
import time
from . import ROOT, OUT, OLD, INPUT, POLICY
from evaluation.framework.formula_design.runtime import read, save, rows, sha, guard


def baseline_check():
    from evaluation.framework.separation_direction.runtime import verify_seal
    frozen, seal = verify_seal()
    reproduced = OUT/'baseline_reproduction'
    previous = read(OLD/'separation_results.json'); current = read(reproduced/'separation_results.json')
    keys = ('GT_MIN_SCORE', 'GT_MEDIAN_SCORE', 'GT_MAX_SCORE', 'HARD_NEGATIVE_MAX_SCORE',
            'MAX_ALL_HARD_TOUCHING_SCORE', 'SCORE_OVERLAP', 'candidate_recall', 'gate_recall')
    equal = all(previous[k] == current[k] for k in keys)
    equal &= previous['diagnostic_points'] == current['diagnostic_points']
    old_selected = list(rows(OLD/'blind/selected_scores.jsonl.gz'))
    new_selected = list(rows(reproduced/'blind/selected_scores.jsonl.gz'))
    equal &= old_selected == new_selected
    for name in ('pair_scores.jsonl.gz', 'direction_evidence.jsonl.gz', 'correlation_edges.jsonl.gz'):
        # gzip container timestamps are irrelevant; canonical decoded bytes/rows are authoritative.
        with gzip.open(OLD/'blind'/name, 'rb') as a, gzip.open(reproduced/'blind'/name, 'rb') as b:
            while True:
                x, y = a.read(1024*1024), b.read(1024*1024)
                if x != y: equal = False; break
                if not x: break
    equal &= current['candidate_recall'] == current['gate_recall'] == 1.
    p = current['primary']
    equal &= (p['GT_CORRELATION_EDGES_RECOVERED'], p['GT_DIRECTION_EDGES_RECOVERED'],
              p['GT_CHAIN_EDGES_RECOVERED']) == (2, 1, 0)
    equal &= abs(current['HARD_NEGATIVE_MAX_SCORE']-.4941788209) < 1e-10
    equal &= abs(current['GT_MIN_SCORE']-.1761987553) < 1e-10
    receipt = dict(status='PASS' if equal else 'V5_BASELINE_REPRODUCTION_FAILED',
                   identity={k: frozen[k] for k in ('algorithm_version', 'formula_hash', 'config_hash', 'implementation_hash', 'mapping_digest')},
                   scores={k: current[k] for k in keys}, primary=p,
                   candidate_digest=seal['candidate_digest'], candidate_count=seal['candidate_count'], member_count=seal['member_count'],
                   regression=read(OLD/'summary.json')['REGRESSION'],
                   old_regression_xml_sha256=sha(OLD/'regression.xml'),
                   reproduced_seal_sha256=sha(reproduced/'score_seal.json'),
                   complete_member_scores_directions_edges_recomputed=equal)
    save(OUT/'baseline_receipt.json', receipt)
    if not equal: raise ValueError('V5_BASELINE_REPRODUCTION_FAILED')
    return receipt


def freeze(stage):
    from app.config import read_yaml
    from app.correlation.semantic_repair.models import Policy
    from app.utils.stable_id import content_digest
    from evaluation.framework.separation_direction.runtime import verify_seal
    frozen, seal = verify_seal()
    if read(OUT/'baseline_receipt.json')['status'] != 'PASS': raise ValueError('baseline_required')
    folder = OUT/stage; folder.mkdir(exist_ok=True)
    if (folder/'formula_freeze.json').exists(): raise ValueError('immutable_freeze_exists')
    policy = Policy.model_validate(read_yaml(POLICY)).model_dump(by_alias=True)
    files = {p.relative_to(ROOT).as_posix(): sha(p) for parent in
             (ROOT/'backend/app/correlation/semantic_repair', ROOT/'evaluation/framework/semantic_repair')
             for p in sorted(parent.glob('*.py'))}
    files[POLICY.relative_to(ROOT).as_posix()] = sha(POLICY)
    selected = read(OUT/'development/selection.json') if stage == 'final' else None
    identity = dict(baseline_formula=frozen['formula_hash'], implementation=files, policy=policy, selection=selected)
    save(folder/'formula_freeze.json', dict(algorithm_version=policy['version'], schema_version=policy['schema_version'],
         formula_hash=content_digest(identity), implementation_hash=content_digest(files), implementation_files=files,
         config_hash=content_digest(dict(baseline_config=frozen['config_hash'], policy=policy)), mapping_digest=frozen['mapping_digest'],
         policy=policy, policy_hash=content_digest(policy), baseline_seal_sha256=sha(OLD/'score_seal.json'),
         baseline_freeze_sha256=sha(OLD/'formula_freeze.json'), canonical_inputs=frozen['canonical_inputs'],
         candidate_digest=seal['candidate_digest'], candidate_count=seal['candidate_count'], member_count=seal['member_count'],
         baseline_sources={**frozen['baseline_sources'], **frozen['implementation_files']},
         baseline_receipt_sha256=sha(OUT/'baseline_receipt.json'), selection=selected,
         design_document_sha256=sha(OUT/'DESIGN.md'), development_previously_saw_labels=True,
         post_evaluation_parameter_changes=0, candidate_gate_changed=False, production_registered=False,
         final_calibration=False, t2_executed=False))
    print('FORMULA_FROZEN', stage, flush=True)


def verify_freeze(stage):
    f = read(OUT/stage/'formula_freeze.json')
    for name, expected in {**f['baseline_sources'], **f['implementation_files']}.items():
        if sha(ROOT/name) != expected: raise ValueError('implementation_changed:'+name)
    for name, expected in f['canonical_inputs'].items():
        if sha(Path(name)) != expected: raise ValueError('input_changed:'+name)
    if sha(OLD/'score_seal.json') != f['baseline_seal_sha256']: raise ValueError('old_seal_changed')
    if sha(OUT/'DESIGN.md') != f['design_document_sha256']: raise ValueError('prospective_design_changed')
    return f


def verify_seal(stage):
    f = verify_freeze(stage); folder = OUT/stage; s = read(folder/'score_seal.json')
    if s['ground_truth_loaded'] or s['formula_freeze_sha256'] != sha(folder/'formula_freeze.json'):
        raise ValueError('unsealed_predictions')
    for name, expected in s['files'].items():
        if sha(folder/name) != expected: raise ValueError('prediction_changed:'+name)
    return f, s


def write(stream, row):
    stream.write(json.dumps(row, ensure_ascii=False, separators=(',', ':'), allow_nan=False)+'\n')


def blind(stage):
    folder = OUT/stage
    if (folder/'evaluation_started.json').exists() or (folder/'score_seal.json').exists():
        raise ValueError('single_use_before_evaluation')
    frozen = verify_freeze(stage); policy = frozen['policy']; op = policy['observation_policy']
    from app.adapters.base import AdapterSettings
    from app.models import CanonicalAlert, DedupeGroup, Entity
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.services.storage import restore_config
    from app.correlation.separation_direction.formula import aggregate as old_aggregate
    from app.correlation.separation_direction.evidence import alias_groups, value
    from app.correlation.semantic_repair.evidence import hierarchy, direction
    from app.correlation.semantic_repair.formula import aggregate, chain_admission
    from app.correlation.semantic_repair.models import PairResult, CorrelationEdge
    from app.correlation.semantic_repair.graph import reconstruct
    from app.utils.stable_id import id_for
    # Preload lazy dependencies before the tripwire; no module or data import
    # is allowed to silently introduce an external read during replay.
    from app.correlation.evidence_v4 import EvidenceV4Evaluator
    from app.dedup.observation import ObservationMatcher
    from app.services.capacity import execution_state
    from app.correlation import entity_bridges
    destination = folder/'blind'; destination.mkdir(exist_ok=False)
    input_paths = [INPUT/n for n in ('canonical.jsonl.gz', 'dedupe.jsonl.gz', 'entities.jsonl.gz')]
    baseline_freeze = ROOT/'outputs/v5_evidence_semantics_final/formula_freeze.json'
    allowed = [*input_paths, OLD/'blind/pair_scores.jsonl.gz', baseline_freeze]
    designs = policy['designs'] if stage == 'development' else [frozen['selection']['design']]
    best = {design: {} for design in designs}; count = 0; counts = Counter(); start = time.perf_counter()
    with guard(allowed, destination) as (events, reads):
        old = read(baseline_freeze); config = restore_config(old['effective']['algorithm'])
        settings = {k: AdapterSettings(**v) for k, v in old['effective']['sources'].items()}
        alerts = [CanonicalAlert.model_validate(r) for r in rows(input_paths[0])]
        groups = [DedupeGroup.model_validate(r) for r in rows(input_paths[1])]
        entities = [Entity.model_validate(r) for r in rows(input_paths[2])]
        if len(alerts) != 10051: raise ValueError('dataset_incomplete')
        index = AlertIndex(alerts, groups, entities); scorer = CorrelationScorer(index, config, settings)
        with gzip.open(destination/'pair_scores.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as output, \
             gzip.open(destination/'direction_evidence.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as directions:
            for oldrow in rows(OLD/'blind/pair_scores.jsonl.gz'):
                count += 1
                legacy = old_aggregate(oldrow['baseline'], oldrow['groups'], oldrow['transition'], op)
                if abs(legacy['final_score']-oldrow['score']) > 1e-12: raise ValueError('baseline_score_drift')
                a, b = [index.alerts[i] for i in oldrow['support_pair']]
                first, second = sorted((a, b), key=lambda x: (index.times[x.alert_id], x.alert_id))
                relations, _ = scorer.verify_relations(first, second)
                rs = [r.json_data() for r in relations]
                d = direction(first, second, index, settings, op,
                              hard=oldrow['baseline']['gate']['hard_contradiction'], relations=rs)
                tier = hierarchy(first, second, index, op, d, config.algorithm.entity)
                gs = alias_groups(oldrow['groups'], a, b, index)
                variants = {design: aggregate(oldrow['baseline'], gs, tier, policy, design) for design in designs}
                row = PairResult.model_validate(dict(support_pair=oldrow['support_pair'], support_key=oldrow['support_key'],
                    valid=oldrow['valid'], old_score=oldrow['score'], baseline=oldrow['baseline'], groups=gs,
                    hierarchy=tier, direction=d, variants=variants, policy_hash=frozen['policy_hash']))
                for key in ('identity_evidence', 'role_evidence', 'behavior_evidence', 'binding_evidence'):
                    for clue in tier[key]:
                        for p in clue['provenance']:
                            if value(index.alerts[p['alert_id']], p['pointer']) is None: raise ValueError('unresolved_pointer')
                data = row.model_dump(mode='json'); write(output, data)
                write(directions, dict(support_pair=row.support_pair, evidence_orientation=[first.alert_id, second.alert_id], **d))
                counts['tier_'+str(tier['level'])] += 1; counts['gate_passed'] += row.baseline['gate']['passed']
                if row.valid and row.baseline['gate']['passed']:
                    for design in designs:
                        score = variants[design]['final_score']; key = tuple(row.support_key)
                        tie = (-score, a.timestamp, b.timestamp, a.alert_id, b.alert_id)
                        if key not in best[design] or tie < best[design][key][0]:
                            keep = score >= min(policy['diagnostic_operating_points'])
                            best[design][key] = (tie, row if keep else None, score, d['status'])
                if count % 25000 == 0: print(json.dumps(dict(stage=stage, members=count, seconds=time.perf_counter()-start)), flush=True)
        if count != frozen['member_count']: raise ValueError('member_coverage_changed')
        for design in designs:
            dfolder = destination/design; dfolder.mkdir()
            edges = []
            with gzip.open(dfolder/'selected_scores.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as output:
                for key, (tie, obj, score, status) in sorted(best[design].items()):
                    write(output, dict(support_key=key, support_pair=list(tie[-2:]), score=score, direction_status=status))
                    if obj is None: continue
                    data = dict(source_alert_id=key[0], target_alert_id=key[1], score=score, design=design,
                                support=obj, score_breakdown=obj.variants[design])
                    data['edge_id'] = id_for('CorrelationEdge', data); edges.append(CorrelationEdge.model_validate(data))
            with gzip.open(dfolder/'correlation_edges.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as output:
                for edge in edges: write(output, edge.model_dump(mode='json'))
            # Threshold files are actual edge materializations, not estimated
            # counts from scores. They are diagnostic correlation outputs.
            for point in policy['diagnostic_operating_points']:
                with gzip.open(dfolder/('correlation_'+str(point).replace('.', '_')+'.jsonl.gz'), 'wt', encoding='utf8', compresslevel=1) as output:
                    for edge in edges:
                        if edge.score >= point: write(output, edge.model_dump(mode='json'))
            policies = policy['chain_policies'] if stage == 'development' else [frozen['selection']['chain_policy']]
            for variant in policies:
                graph_folder = dfolder/('policy_'+variant); graph_folder.mkdir()
                # Persist all support edges that can influence components or a
                # chain; lower-score links remain explicitly identified.
                support = [e for e in edges if e.score >= .65 or chain_admission(e.score,
                    e.support.direction.model_dump(mode='json'), e.support.hierarchy, e.support.baseline['gate'], policy, variant)['accepted']]
                inc, nodes, chains, diags = reconstruct(index, support, scorer, policy, variant)
                for name, records in (('correlation_edges', support), ('incidents', inc), ('nodes', nodes),
                                      ('chain_edges', chains), ('diagnostics', diags)):
                    with gzip.open(graph_folder/(name+'.jsonl.gz'), 'wt', encoding='utf8', compresslevel=1) as output:
                        for record in records: write(output, record.model_dump(mode='json') if hasattr(record, 'model_dump') else record)
                save(graph_folder/'summary.json', dict(design=design, chain_policy=variant, chain_edges=len(chains),
                     incidents=len(inc), original_alerts_retained=len({a for n in nodes for a in n.alert_ids}),
                     component_sizes=sorted([len(i.alert_ids) for i in inc], reverse=True),
                     candidate_schema='5.3-candidate', production_published=False))
                print('GRAPH_SEALED', design, variant, len(chains), flush=True)
        save(destination/'summary.json', dict(raw_alerts=len(alerts), representatives=index.N, member_count=count,
             candidate_count=frozen['candidate_count'], candidate_digest=frozen['candidate_digest'],
             unchanged_nominations_reused=True, complete_original_member_replay=True, schema_validated_pairs=count,
             elapsed_seconds=time.perf_counter()-start, counts=dict(counts)))
        save(destination/'guard_receipt.json', dict(ground_truth_loaded=False, rejected_events=events,
             non_code_reads=sorted(reads), canonical_alerts_mutated=False, pointers_resolved=True, t2_read=False))
    save(folder/'score_seal.json', dict(status='completed', ground_truth_loaded=False,
         formula_freeze_sha256=sha(folder/'formula_freeze.json'), member_count=count,
         score_sealed=True, direction_sealed=True, graph_sealed=True,
         files={p.relative_to(folder).as_posix(): sha(p) for p in sorted(destination.rglob('*')) if p.is_file()}))
    print('SCORE_DIRECTION_GRAPH_SEALED', stage, flush=True)


if __name__ == '__main__':
    import sys
    action = sys.argv[1]
    if action == 'baseline': baseline_check()
    elif action == 'freeze': freeze(sys.argv[2])
    elif action == 'blind': blind(sys.argv[2])

"""Assemble frozen Stage relation graphs. Subcommands: run and verify."""
import argparse
import builtins
from contextlib import contextmanager
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.evidence_trace import ChainTrace
from app.evidence_trace.snapshot import file_sha256
from app.stage_chains import StageAttackChain, StageChainResult, assemble_attack_chains, validate_assembly
from app.stage_chains.models import VERSION
from app.stage_chains.snapshot import assert_source_unchanged, load_stage_graph, safe_snapshot_path
from app.utils.stable_id import canonical_json, content_digest, id_for


@contextmanager
def assembly_guard(writable_roots):
    """No truth IO/imports and no upstream business algorithm calls/imports.

    Calls to already imported functions are trapped by tests as well. Reading
    sealed Stage/Relation/Trace schemas does not rerun their business algorithms.
    """
    old_open, old_io, old_import = builtins.open, io.open, builtins.__import__
    counts = dict(PRODUCTION_GT_READS=0, PROHIBITED_ALGORITHM_IMPORTS=0)
    def check(path, mode):
        if isinstance(path, (str, bytes, Path)):
            p = Path(path.decode() if isinstance(path, bytes) else path).resolve()
            if {s.casefold() for s in p.parts} & {'evaluation', 'ground_truth', 'historical_gt', 'archive'} or p.stem.casefold() in {'ground_truth', 'labels', 'attacks', 'gold_chain'}:
                counts['PRODUCTION_GT_READS'] += 1
                raise AssertionError('stage_chain_truth_io_forbidden')
            if any(c in mode for c in 'wax+') and not any(p.is_relative_to(root) for root in writable_roots):
                raise AssertionError('stage_chain_write_outside_new_outputs')
    def opened(path, mode='r', *args, **kwargs):
        check(path, mode)
        return old_open(path, mode, *args, **kwargs)
    def io_opened(path, mode='r', *args, **kwargs):
        check(path, mode)
        return old_io(path, mode, *args, **kwargs)
    def importing(name, *args, **kwargs):
        if name == 'evaluation' or name.startswith(('evaluation.', 'app.chains', 'app.correlation', 'app.incidents',
                'app.ai', 'app.adapters', 'app.entities.extraction', 'app.entities.front_data', 'app.entities.context',
                'app.community.builder', 'app.community.index',
                'app.stage_relations.analysis', 'app.stage_relations.evidence', 'app.stage_relations.time',
                'app.stages.aggregation', 'app.stages.behavior', 'app.stages.resolver')):
            counts['PROHIBITED_ALGORITHM_IMPORTS'] += 1
            raise AssertionError('stage_chain_upstream_or_truth_import_forbidden')
        return old_import(name, *args, **kwargs)
    builtins.open, io.open, builtins.__import__ = opened, io_opened, importing
    try:
        yield counts
    finally:
        builtins.open, io.open, builtins.__import__ = old_open, old_io, old_import


def save(path, value):
    path.write_text(canonical_json(value)+'\n', encoding='utf8')


def statistics(result, snapshot, validation):
    chains = result.chains
    alerts = {aid for stage in snapshot.stages.values() for aid in stage.alert_ids}
    return dict(TASK_RESULT='SUCCESS', ATTACK_CHAIN_RECONSTRUCTION_STARTED=True,
        ATTACK_CHAIN_RECONSTRUCTION_COMPLETE=True, INPUT_ALERTS=len(alerts), STAGE_COUNT=len(snapshot.stages),
        STAGE_RELATION_COUNT=len(snapshot.relations), ATTACK_CHAIN_COUNT=len(chains),
        MULTI_STAGE_CHAIN_COUNT=sum(not c.single_stage for c in chains),
        SINGLE_STAGE_CHAIN_COUNT=sum(c.single_stage for c in chains),
        CHAIN_STAGE_TOTAL=sum(c.stage_count for c in chains), CHAIN_RELATION_TOTAL=sum(c.relation_count for c in chains),
        STRONG_DIRECTED_RELATION_COUNT=sum(c.strong_directed_count for c in chains),
        STRONG_UNDIRECTED_RELATION_COUNT=sum(c.strong_undirected_count for c in chains),
        WEAK_DIRECTED_RELATION_COUNT=sum(c.weak_directed_count for c in chains),
        MAX_CHAIN_STAGE_COUNT=max((c.stage_count for c in chains), default=0),
        MAX_CHAIN_RELATION_COUNT=max((c.relation_count for c in chains), default=0),
        DIRECTED_CYCLE_CHAIN_COUNT=sum(c.has_directed_cycle for c in chains),
        CHAIN_EVIDENCE_TRACE_SUPPORTED=True, CHAIN_TRACE_SUPPORTED=True,
        DANGLING_STAGE_REFERENCE_COUNT=validation.dangling_stage_reference_count,
        DANGLING_RELATION_REFERENCE_COUNT=validation.dangling_relation_reference_count,
        DANGLING_EVIDENCE_REFERENCE_COUNT=validation.dangling_evidence_reference_count,
        RAW_ALERTS_VERIFIED=validation.raw_alerts_verified,
        EVIDENCE_POINTERS_RESOLVED=validation.evidence_pointers_resolved,
        GROUND_TRUTH_LEAKAGE=False, CURRENT_PIPELINE_STAGE='ATTACK_CHAIN_RECONSTRUCTION_COMPLETE',
        NEXT_STAGE_NOT_STARTED=True)


def assembly_identity(snapshot):
    # Content identity cannot depend on manifest bytes that may themselves
    # contain an absolute audit path. Provenance hashes are recorded separately.
    policy = dict(version=VERSION, membership='connected_components_all_existing_relations',
                  entry_exit='existing_directed_relations_only', cycle='preserve_and_report', main_path='not_computed')
    config_snapshot = dict(assembly=policy, input_digest=snapshot.input_digest)
    config_hash = content_digest(config_snapshot)
    analysis_id = id_for('AnalysisRecord', dict(input_alert_ids=sorted({a for s in snapshot.stages.values() for a in s.alert_ids}),
        config_hash=config_hash, algorithm_version=VERSION, schema_version='1.0'))
    return config_snapshot, config_hash, analysis_id


def execute(relation_manifest, evidence_manifest, output):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT/'outputs') or output.exists():
        raise ValueError('assembly_requires_new_output_directory')
    with assembly_guard([]):
        snapshot, receipt = load_stage_graph(ROOT, relation_manifest, evidence_manifest)
    config_snapshot, config_hash, analysis_id = assembly_identity(snapshot)
    domain, details = ROOT/'data/processed'/analysis_id, ROOT/'outputs/analyses'/analysis_id
    if domain.exists() or details.exists():
        raise ValueError('assembly_snapshot_already_exists')
    with assembly_guard([output, domain, details]) as access:
        result = assemble_attack_chains(snapshot)
        validation = validate_assembly(result, snapshot)
        validation.require_valid()
        assert_source_unchanged(receipt)
        output.mkdir(parents=True)
        domain.mkdir(parents=True)
        details.mkdir(parents=True)
        # Chain objects contain references only, with no new Stage or edge objects.
        encoded = ''.join(c.canonical_json()+'\n' for c in result.chains)
        (domain/'stage_attack_chains.jsonl').write_text(encoded, encoding='utf8')
        save(output/'result.json', result.model_dump(mode='json'))
        save(output/'chains.json', [c.model_dump(mode='json') for c in result.chains])
        # Existing ChainTrace schema is reused; its persisted EvidenceTrace source
        # files remain untouched. Raw payloads are never copied into chain outputs.
        (output/'chain_traces.jsonl').write_text(''.join(snapshot.chain_trace(c).canonical_json()+'\n' for c in result.chains), encoding='utf8')
        save(output/'chain_refs.json', [dict(chain_id=c.chain_id, stage_ids=c.stage_ids, relation_ids=c.relation_ids) for c in result.chains])
        save(output/'validation.json', validation.as_dict())
        save(output/'source_receipt.json', receipt)
        save(output/'contracts.json', dict(StageAttackChain=StageAttackChain.model_json_schema(), StageChainResult=StageChainResult.model_json_schema()))
        save(details/'frequency_snapshot.json', dict(stage_count=len(snapshot.stages), relation_count=len(snapshot.relations)))
        (details/'diagnostics.jsonl').write_text(''.join(canonical_json(dict(chain_id=c.chain_id,
            rule='preserve_existing_directed_cycle', has_directed_cycle=True))+'\n' for c in result.chains if c.has_directed_cycle), encoding='utf8')
        summary = statistics(result, snapshot, validation)
        summary.update(access)
        save(output/'summary.json', summary)
        # Copy-free examples: Chain -> persisted Trace ref -> existing witness
        # and raw fingerprint. The resolver, not this report, reads raw content.
        examples = []
        for chain in result.chains:
            entries = []
            for kind in ('STAGE', 'STRONG_DIRECTED_EDGE', 'STRONG_UNDIRECTED_EDGE', 'WEAK_DIRECTED_RELATION'):
                ref = next((ref for ref in chain.evidence_refs if ref.subject_type == kind), None)
                if ref:
                    trace = snapshot.resolve_trace(ref)
                    entries.append(dict(trace_ref=ref.model_dump(mode='json'),
                        witness_alert_ids=trace.witness_alert_ids, winning_witness_alert_ids=trace.winning_witness_alert_ids,
                        raw_evidence_refs=[r.model_dump(mode='json') for r in trace.raw_evidence_refs],
                        direction_basis=trace.direction_basis, temporal_order_is_causal_evidence=False))
            examples.append(dict(chain_id=chain.chain_id, examples=entries))
        save(output/'examples.json', examples)
        assert_source_unchanged(receipt)
        artifacts = {p.relative_to(ROOT).as_posix():file_sha256(p) for folder in (domain, details, output)
                     for p in sorted(folder.iterdir()) if p.is_file()}
        manifest = dict(status='sealed', analysis_id=analysis_id, algorithm_version=VERSION,
            config_hash=config_hash, config_snapshot=config_snapshot, input_digest=result.input_digest,
            source_analysis_id=snapshot.source_analysis_id,
            source_manifest_sha256=dict(relations=receipt[str(Path(relation_manifest).resolve())],
                                        evidence=receipt[str(Path(evidence_manifest).resolve())]),
            relation_manifest=Path(relation_manifest).resolve().relative_to(ROOT).as_posix(),
            evidence_manifest=Path(evidence_manifest).resolve().relative_to(ROOT).as_posix(),
            artifacts=artifacts, summary=summary,
            limitations=['Connected structure does not confirm one real-world attack.',
                'Entry/exit candidates include weak temporal arrows and are not confirmed causal entry/exit.',
                'All existing cycles and unresolved strong directions are preserved; no main path is inferred.'])
        save(details/'manifest.json', manifest)
        save(output/'manifest.json', manifest)
        print(json.dumps(summary, indent=2))
        return result


def verify(output):
    output = safe_snapshot_path(ROOT, output)
    with assembly_guard([output]) as access:
        manifest = json.loads((output/'manifest.json').read_text(encoding='utf8'))
        if manifest['status'] != 'sealed' or manifest['algorithm_version'] != VERSION:
            raise ValueError('requires_sealed_stage_chain_snapshot')
        for ref, digest in manifest['artifacts'].items():
            path = safe_snapshot_path(ROOT, ROOT/ref)
            if file_sha256(path) != digest:
                raise ValueError('assembly_artifact_hash_mismatch:' + ref)
        snapshot, expected_receipt = load_stage_graph(ROOT, ROOT/manifest['relation_manifest'], ROOT/manifest['evidence_manifest'])
        receipt = json.loads((output/'source_receipt.json').read_text(encoding='utf8'))
        if receipt != expected_receipt:
            raise ValueError('assembly_source_receipt_mismatch')
        assert_source_unchanged(receipt)
        expected_config, expected_hash, expected_analysis = assembly_identity(snapshot)
        if (manifest['config_snapshot'], manifest['config_hash'], manifest['analysis_id'], manifest['input_digest'], manifest['source_analysis_id']) != (
                expected_config, expected_hash, expected_analysis, snapshot.input_digest, snapshot.source_analysis_id):
            raise ValueError('assembly_manifest_identity_mismatch')
        result = StageChainResult.model_validate_json((output/'result.json').read_text(encoding='utf8'))
        validation = validate_assembly(result, snapshot)
        validation.require_valid()
        if result != assemble_attack_chains(snapshot):
            raise ValueError('reloaded_component_membership_or_metadata_differs')
        chains = [StageAttackChain.model_validate(c) for c in json.loads((output/'chains.json').read_text(encoding='utf8'))]
        if chains != result.chains:
            raise ValueError('chain_json_export_mismatch')
        domain = ROOT/'data/processed'/manifest['analysis_id']
        stored = [StageAttackChain.model_validate_json(line) for line in (domain/'stage_attack_chains.jsonl').read_text(encoding='utf8').splitlines()]
        if stored != result.chains:
            raise ValueError('chain_domain_export_mismatch')
        traces = [ChainTrace.model_validate_json(line) for line in (output/'chain_traces.jsonl').read_text(encoding='utf8').splitlines()]
        if traces != [snapshot.chain_trace(c) for c in result.chains]:
            raise ValueError('chain_trace_export_mismatch')
        references = [dict(chain_id=c.chain_id, stage_ids=c.stage_ids, relation_ids=c.relation_ids) for c in result.chains]
        if references != json.loads((output/'chain_refs.json').read_text(encoding='utf8')):
            raise ValueError('chain_reference_export_mismatch')
        summary = json.loads((output/'summary.json').read_text(encoding='utf8'))
        if summary != manifest['summary'] or any(summary.get(k) != v for k,v in statistics(result, snapshot, validation).items()):
            raise ValueError('chain_summary_mismatch')
        verified = dict(CHAIN_OBJECTS_RELOADED=len(chains), EXISTING_STAGE_RELATION_TRACE_EXACT=True,
            CHAIN_STAGE_TOTAL=sum(c.stage_count for c in chains), CHAIN_RELATION_TOTAL=sum(c.relation_count for c in chains),
            CHAIN_TRACE_RAW_RESOLUTION_PASSED=True, **validation.as_dict(), **access)
        save(output/'verification.json', verified)
        print(json.dumps(verified, indent=2))
        return verified


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run')
    run.add_argument('--relations', type=Path, default=ROOT/'outputs/stage_relations_v1/manifest.json')
    run.add_argument('--evidence', type=Path, default=ROOT/'outputs/evidence_trace_v1/manifest.json')
    run.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'run':
        execute(args.relations, args.evidence, args.output)
    else:
        verify(args.output)

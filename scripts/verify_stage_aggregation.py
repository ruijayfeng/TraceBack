"""Replay Stage from sealed source facts; verify raw closure and stable exports.

This verifier consumes security alerts and predictions only. Frozen-file hash
auditing is intentionally separate and supplies no facts to the algorithm.
"""
import argparse
import builtins
from collections import Counter
import gzip
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))

from app.adapters.base import AdapterSettings
from app.community import CommunityRun, load_community_config
from app.community.models import CommunityResult, IncidentCandidate
from app.config import read_yaml
from app.models import CanonicalAlert, Entity
from app.stages import aggregate_stages, load_stage_config, Stage
from app.utils.stable_id import canonical_json
from run_community_builder import save, sha
from run_stage_aggregation import execute


def verify(input_path, output, baseline_manifest):
    input_path, output = Path(input_path), Path(output)
    original_open, original_import = Path.open, builtins.__import__
    original_builtin_open, original_io_open = builtins.open, io.open
    guarded_reads = Counter()
    def check_path(path):
        if isinstance(path, (str, bytes, Path)):
            parts = Path(path.decode() if isinstance(path, bytes) else path).parts
        else:
            return
        if any(part.casefold() in {'evaluation', 'ground_truth', 'archive', 'historical_gt'} for part in parts):
            raise AssertionError('prohibited_truth_path_read')
    def guarded_open(path, *args, **kwargs):
        check_path(path)
        guarded_reads['path_open'] += 1
        return original_open(path, *args, **kwargs)
    def guarded_builtin_open(path, *args, **kwargs):
        check_path(path)
        guarded_reads['builtin_open'] += 1
        return original_builtin_open(path, *args, **kwargs)
    def guarded_io_open(path, *args, **kwargs):
        check_path(path)
        guarded_reads['io_open'] += 1
        return original_io_open(path, *args, **kwargs)
    def guarded_import(name, *args, **kwargs):
        if name.startswith(('evaluation', 'app.chains', 'app.ai.explanation', 'app.ai.report')):
            raise AssertionError('prohibited_downstream_or_truth_import')
        return original_import(name, *args, **kwargs)
    Path.open, builtins.__import__ = guarded_open, guarded_import
    builtins.open, io.open = guarded_builtin_open, guarded_io_open
    try:
        manifest = execute(input_path, output, baseline_manifest=baseline_manifest)
        domain = ROOT/'data/processed'/manifest['analysis_id']
        hashes_before = {name:sha(ROOT/name) for name in manifest['artifacts']}
        # Repeat actual ingress -> entities/context -> Community -> Behavior -> Stage.
        repeated = execute(input_path, output, baseline_manifest=baseline_manifest)
        assert repeated == manifest
        assert hashes_before == {name:sha(ROOT/name) for name in manifest['artifacts']}
        def read(name, model):
            with gzip.open(domain/name, 'rt', encoding='utf8') as stream:
                return [model.model_validate_json(line) for line in stream]
        alerts = read('stage_source_alerts.jsonl.gz', CanonicalAlert)
        entities = read('stage_source_entities.jsonl.gz', Entity)
        communities = read('stage_source_communities.jsonl.gz', IncidentCandidate)
        stages = read('stages.jsonl.gz', Stage)
        routing = read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
        settings = {v['source_namespace']:AdapterSettings(**v) for v in routing.values()}
        policy = load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
        community_config = load_community_config(ROOT/'configs/community-v1.yaml')
        community_result = CommunityResult(config_hash=manifest['config_hash'],
            input_fingerprint=manifest['input_fingerprint'], incident_candidates=communities,
            diagnostics=[], statistics={})
        # Replay saved annotations, never recompute Behavior after Community.
        from app.stages.models import BehaviorAnnotation
        annotations = [b.model_copy(update=dict(community_id=None)) for b in read('behaviors.jsonl.gz', BehaviorAnnotation)]
        source = CommunityRun(alerts, entities, community_result, behaviors=annotations, behavior_config_hash=policy.digest)
        result = aggregate_stages(source, settings, community_config, policy)
        reversed_source = CommunityRun(list(reversed(alerts)), list(reversed(entities)),
            community_result.model_copy(update=dict(incident_candidates=list(reversed(communities)))),
            behaviors=list(reversed(annotations)), behavior_config_hash=policy.digest)
        reverse = aggregate_stages(reversed_source, settings, community_config, policy)
        assert reverse == result
        assert result.stages == stages
        # Do not claim AI-response replay without its provider/cache being used.
        if manifest['config_snapshot']['ai']['configured']:
            raise ValueError('verification_requires_saved_ai_response_replay')
        behavior_export = json.loads((output/'behaviors.json').read_text(encoding='utf8'))
        assert behavior_export == [b.model_dump(mode='json') for b in result.behaviors]
        aa = {a.alert_id:a for a in alerts}
        cc = {c.community_id:c for c in communities}
        ee = {e.entity_id:e for e in entities}
        trace = json.loads((output/'trace_map.json').read_text(encoding='utf8'))
        with input_path.open(encoding='utf8') as stream:
            native = {row['event_id']:row['event'] for line in stream if (row:=json.loads(line))}
        assert len(native) == len(trace) == len(alerts)
        for row in trace:
            assert aa[row['alert_id']].raw_alert == native[row['event_id']]
        covered, pointers = [], 0
        for stage in stages:
            Stage.model_validate(stage, context=dict(alerts=aa, entities=ee, communities=cc))
            covered.extend(stage.alert_ids)
            assert set(stage.alert_ids) <= set(cc[stage.community_id].alert_ids)
            for basis in stage.aggregation_basis:
                for pointer in basis.evidence:
                    pointer.resolve(aa)
                    pointers += 1
        for annotation in result.behaviors:
            for pointer in annotation.evidence:
                pointer.resolve(aa)
                pointers += 1
        assert sorted(covered) == sorted(aa) and len(covered) == len(set(covered))
        verification = dict(ALERTS_COVERED_EXACTLY_ONCE=len(covered),
            RAW_ALERTS_MATCH_FROZEN_NATIVE_INPUT=len(trace), STAGE_ALERT_RAW_TRACEABILITY=1.0,
            BOUND_EVIDENCE_POINTERS_RESOLVED=pointers, REPEATED_PIPELINE_BYTE_STABLE=True,
            REVERSED_INPUT_RESULT_IDENTICAL=True, COMMUNITY_BASELINE_UNCHANGED=True,
            GT_READS=0, NEXT_STAGE_NOT_STARTED=True, guarded_io_calls=dict(guarded_reads))
        save(output/'verification.json', verification)
        print(json.dumps(verification,indent=2))
        return verification
    finally:
        Path.open, builtins.__import__ = original_open, original_import
        builtins.open, io.open = original_builtin_open, original_io_open


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'outputs/behavior_stage_v1')
    parser.add_argument('--baseline-manifest', type=Path, required=True)
    args = parser.parse_args()
    verify(args.input, args.output, args.baseline_manifest)

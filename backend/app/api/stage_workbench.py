"""Read projections for sealed Stage chains, using their existing evidence resolver.

Two independent, read-only sources are served through one catalog:

* the official ⑨ Attack Chain Reconstruction artifact
  (``reconstruction.py`` line, contract ``attack-chain-reconstruction-v1``), and
* the legacy Stage Attack Chain assembly snapshots
  (``assembly.py`` line, contract ``stage-attack-chain-v1``).

Neither line is re-run, merged, or rewritten; the Adapter only projects each
sealed artifact into a Workbench display model. The official ⑨ artifact is the
default / latest / official entry.
"""
import json
import threading
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from app.models.base import AnalysisID, AlertID
from app.services.queries import QueryError
from app.services.storage import checked_id
from app.stage_chains import StageChainResult, validate_assembly
from app.stage_chains.models import VERSION
from app.stage_chains.snapshot import load_stage_graph, safe_snapshot_path
from app.stage_chains.stage9_reader import Stage9ArtifactReader
from app.evidence_trace.snapshot import file_sha256

# The official ⑨ artifact directory, relative to the project root. It is the
# primary, latest, official fact source consumed by this workbench.
STAGE9_ARTIFACT = 'outputs/stage9_formal_acceptance_20261022/run1'


def _stage9_analysis_id():
    """Stable analysis_id for the official ⑨ artifact.

    Derived deterministically from the artifact identity so it never changes
    while the sealed artifact is unchanged, and remains distinct from every
    legacy ``ana_*`` assembly snapshot.
    """
    return 'ana_' + sha256(('stage9:' + STAGE9_ARTIFACT).encode('utf-8')).hexdigest()


STAGE9_ANALYSIS_ID = _stage9_analysis_id()
# Explicit source registry: preserve the previously displayed measured snapshot
# as a separately named historical reconstruction line, never as fallback.
MEASURED_ARTIFACT = 'outputs/attack125_final_rerun_20261023_measured'
MEASURED_ID = 'ana_' + sha256(('stage9:' + MEASURED_ARTIFACT).encode('utf8')).hexdigest()
BASELINES = {STAGE9_ANALYSIS_ID: STAGE9_ARTIFACT, MEASURED_ID: MEASURED_ARTIFACT}


class StageWorkbench:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.cache = {}
        self.lock = threading.Lock()
        from app.services.stage_runs import StageRunService
        self.runs = StageRunService(self.root)

    def manifest_path(self, analysis_id):
        return self.root / 'outputs/analyses' / checked_id(analysis_id) / 'manifest.json'

    def is_stage9(self, analysis_id):
        return analysis_id in BASELINES or (self.runs.directory(analysis_id) / 'run.json').is_file()

    def stage9_reader(self, analysis_id=STAGE9_ANALYSIS_ID):
        if analysis_id in BASELINES:
            return Stage9ArtifactReader(self.root, self.root / BASELINES[analysis_id],
                                        require_manifest=analysis_id == STAGE9_ANALYSIS_ID)
        return self.runs.reader(analysis_id)

    def reader_for(self, analysis_id):
        # Keep the historical no-argument primary-reader extension point.
        return self.stage9_reader() if analysis_id == STAGE9_ANALYSIS_ID else self.stage9_reader(analysis_id)

    def stage9_projection(self, analysis_id, method, *args):
        try:
            return getattr(self.reader_for(analysis_id), method)(*args)
        except (OSError, ValueError, KeyError) as exc:
            raise QueryError(409, 'stage_snapshot_integrity_error') from exc

    def catalog(self):
        items = []

        # -- Primary / official: the sealed ⑨ reconstruction artifact ----------
        for identity, source in BASELINES.items():
            try:
                overview = self.reader_for(identity).overview()
                artifact = self.root / source / 'stage9.json'
                primary = identity == STAGE9_ANALYSIS_ID
                items.append(dict(analysis_id=identity, algorithm_version=overview['contract_version'],
                    input_count=overview['counts']['input_count'], published_at=artifact.stat().st_mtime,
                    official=primary, latest=primary, default=primary, read_only=True,
                    source_stage=9, pipeline='reconstruction.py', filename=source,
                    status='SUCCEEDED', result_available=True, baseline=True))
            except (OSError, ValueError, KeyError):
                pass

        for run in self.runs.history():
            if run['status'] == 'SUCCEEDED':
                items.append(dict(analysis_id=run['run_id'], run_id=run['run_id'],
                    algorithm_version=run['artifact_type'], input_count=run['input_count'],
                    published_at=datetime.fromisoformat(run['created_at']).timestamp(), official=False,
                    latest=False, default=False, read_only=True, source_stage=9,
                    pipeline=run['pipeline'], filename=run['filename'], status=run['status'],
                    result_available=run['result_available']))

        # -- Secondary / legacy: sealed assembly.py snapshots -------------------
        for domain in (self.root / 'data/processed').glob('ana_*/stage_attack_chains.jsonl'):
            try:
                path = self.manifest_path(domain.parent.name)
                manifest = json.loads(path.read_text(encoding='utf8'))
                if (manifest.get('status'), manifest.get('algorithm_version'), manifest.get('analysis_id')) != (
                        'sealed', VERSION, domain.parent.name):
                    continue
                items.append(dict(analysis_id=manifest['analysis_id'], algorithm_version=VERSION,
                    input_count=manifest['summary']['INPUT_ALERTS'], published_at=path.stat().st_mtime,
                    official=False, latest=False, default=False, read_only=True,
                    source_stage=8, pipeline='assembly.py'))
            except (OSError, ValueError, KeyError):
                continue

        items.sort(key=lambda item: (not item.get('official', False), -item['published_at'], item['analysis_id']))
        default = next((item['analysis_id'] for item in items if item.get('official')), None)
        if default is None and items:
            default = items[0]['analysis_id']
        return dict(items=items, default_analysis_id=default)

    def load(self, analysis_id):
        if self.is_stage9(analysis_id):
            return self._load_stage9(analysis_id)
        with self.lock:
            try:
                path = self.manifest_path(analysis_id)
                if not path.is_file():
                    raise QueryError(404, 'stage_analysis_not_found')
                cached = self.cache.get(analysis_id)
                if cached:
                    if all(file_sha256(p) == digest for p, digest in cached['receipt'].items()):
                        return cached
                    self.cache.pop(analysis_id)
                    raise QueryError(409, 'stage_snapshot_integrity_error')
                digest = file_sha256(path)
                manifest = json.loads(path.read_text(encoding='utf8'))
                if (manifest['status'], manifest['algorithm_version'], manifest['analysis_id']) != ('sealed', VERSION, analysis_id):
                    raise QueryError(404, 'stage_analysis_not_found')
                receipt = {str(path): digest}
                for ref, expected in manifest['artifacts'].items():
                    artifact = safe_snapshot_path(self.root, self.root / ref)
                    if file_sha256(artifact) != expected:
                        raise ValueError('artifact_hash_mismatch')
                    receipt[str(artifact)] = expected
                relation_path = safe_snapshot_path(self.root, self.root / manifest['relation_manifest'])
                evidence_path = safe_snapshot_path(self.root, self.root / manifest['evidence_manifest'])
                if (file_sha256(relation_path) != manifest['source_manifest_sha256']['relations'] or
                        file_sha256(evidence_path) != manifest['source_manifest_sha256']['evidence']):
                    raise ValueError('source_manifest_hash_mismatch')
                graph, upstream = load_stage_graph(self.root, relation_path, evidence_path)
                receipt.update(upstream)
                chain_ref = f'data/processed/{analysis_id}/stage_attack_chains.jsonl'
                if chain_ref not in manifest['artifacts']:
                    raise ValueError('chain_artifact_missing')
                chains = [json.loads(line) for line in (self.root / chain_ref).read_text(encoding='utf8').splitlines()]
                result = StageChainResult(source_analysis_id=manifest['source_analysis_id'],
                    input_digest=manifest['input_digest'], chains=chains)
                validate_assembly(result, graph).require_valid()
                if any(file_sha256(p) != h for p, h in receipt.items()):
                    raise ValueError('snapshot_changed_during_load')
                raw_refs = {ref.alert_id: ref for trace in graph.traces.values() for ref in trace.raw_evidence_refs}
                cached = dict(manifest=manifest, graph=graph, result=result, receipt=receipt, raw_refs=raw_refs)
                self.cache[analysis_id] = cached
                return cached
            except QueryError:
                raise
            except (OSError, ValueError, KeyError, TypeError):
                raise QueryError(409, 'stage_snapshot_integrity_error') from None

    def _load_stage9(self, analysis_id=STAGE9_ANALYSIS_ID):
        """Read-only projection of the official ⑨ artifact; never recomputed."""
        with self.lock:
            try:
                reader = self.reader_for(analysis_id)
                overview = reader.overview()
                receipt = {
                    str(reader.stage8_path()): file_sha256(reader.stage8_path()),
                    str(reader.stage9_path()): file_sha256(reader.stage9_path()),
                }
                return dict(kind='stage9', overview=overview, receipt=receipt)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise QueryError(409, 'stage_snapshot_integrity_error') from exc

    def overview(self, analysis_id):
        if self.is_stage9(analysis_id):
            data = self._load_stage9(analysis_id)
            overview = data['overview']
            return dict(analysis_id=analysis_id,
                        algorithm_version=overview['contract_version'], status='sealed',
                        counts=overview['counts'], chains=overview['chains'],
                        stages=overview['stages'], relations=overview['relations'],
                        decisions=overview['decisions'],
                        run_id=analysis_id if analysis_id not in BASELINES else None,
                        data_source=BASELINES.get(analysis_id, str(self.runs.directory(analysis_id) / 'result')),
                        artifact_sha256=data['receipt'],
                        read_only=True, official=analysis_id == STAGE9_ANALYSIS_ID,
                        latest=analysis_id == STAGE9_ANALYSIS_ID, source_stage=9)
        data = self.load(analysis_id)
        graph, chains = data['graph'], data['result'].chains
        stages = [s.model_dump(mode='json', exclude={'aggregation_basis'}) for s in graph.stages.values()]
        relations = [r.model_dump(mode='json', exclude={'primary_evidence', 'supporting_evidence', 'confidence_basis', 'time_facts'})
                     for r in graph.relations.values()]
        return dict(analysis_id=analysis_id, algorithm_version=VERSION, status='sealed',
            counts=dict(input_count=len(data['raw_refs']), stage_count=len(stages), relation_count=len(relations),
                chain_count=len(chains), strong_directed_count=sum(c.strong_directed_count for c in chains),
                strong_undirected_count=sum(c.strong_undirected_count for c in chains),
                weak_directed_count=sum(c.weak_directed_count for c in chains)),
            chains=[c.model_dump(mode='json', exclude={'evidence_refs'}) for c in chains],
            stages=stages, relations=relations)


def install_stage_workbench(app, root):
    service = StageWorkbench(root)
    app.state.stage_workbench = service
    from .stage_runs import install_stage_runs
    install_stage_runs(app, service.runs)
    router = APIRouter(prefix='/api/v1/stage-analyses')

    def no_query(request):
        if request.query_params:
            raise HTTPException(400, 'unknown_query_parameter')

    @router.get('')
    def catalog(request: Request):
        no_query(request)
        return service.catalog()

    @router.get('/{analysis_id}')
    def overview(analysis_id: AnalysisID, request: Request):
        no_query(request)
        return service.overview(analysis_id)

    @router.get('/{analysis_id}/summary')
    def summary(analysis_id: AnalysisID, request: Request):
        no_query(request)
        if service.is_stage9(analysis_id):
            return dict(analysis_id=analysis_id, summary=service.stage9_projection(analysis_id, 'summary'))
        raise QueryError(404, 'summary_not_available_for_legacy')

    @router.get('/{analysis_id}/traces/{subject_id}')
    def trace(analysis_id: AnalysisID, subject_id: str, request: Request):
        no_query(request)
        if service.is_stage9(analysis_id):
            trace = service.stage9_projection(analysis_id, 'trace_projection', subject_id)
            if trace is None:
                raise QueryError(404, 'stage_evidence_not_found')
            return dict(analysis_id=analysis_id, trace=trace,
                        resolved_pointers=trace['resolved_pointers'])
        graph = service.load(analysis_id)['graph']
        if subject_id not in graph.traces:
            raise QueryError(404, 'stage_evidence_not_found')
        original = graph.traces[subject_id]
        return dict(analysis_id=analysis_id, trace=original.model_dump(mode='json'),
            resolved_pointers=[dict(**p.model_dump(mode='json'), value=graph.trace_index.resolve_evidence(p))
                               for p in original.evidence_pointers])

    @router.get('/{analysis_id}/alerts/{alert_id}')
    def raw(analysis_id: AnalysisID, alert_id: AlertID, request: Request):
        no_query(request)
        if service.is_stage9(analysis_id):
            raw_alert = service.stage9_projection(analysis_id, 'raw_alert', alert_id)
            if raw_alert is None:
                raise QueryError(404, 'stage_alert_not_found')
            return dict(analysis_id=analysis_id, raw_alert=raw_alert)
        data = service.load(analysis_id)
        ref = data['raw_refs'].get(alert_id)
        if ref is None:
            raise QueryError(404, 'stage_alert_not_found')
        return dict(analysis_id=analysis_id, raw_ref=ref.model_dump(mode='json'),
                    raw_alert=data['graph'].trace_index.raw_evidence(ref))

    app.include_router(router)
    from .stage_explanations import install_stage_explanations
    install_stage_explanations(app, root, service)

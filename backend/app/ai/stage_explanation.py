"""Sidecar Stage explanations: bounded model drafts, grounding, JSON/MD reports.

Only validated structured selections are published. Arbitrary model prose is
never treated as an evidence-backed fact, entity, direction or confirmed loss.
"""
import json
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, ValidationError

from app.models.base import StrictModel, Text
from app.ai.provider import ProviderError
from .stage_context import VERSION

Code = Literal['insufficient', 'process_execution', 'server_shell', 'file_access', 'credential_file',
               'authentication', 'network', 'http_request', 'sql_pattern', 'traversal_pattern']


class FactSelection(StrictModel):
    fact_id: Text
    evidence_refs: Annotated[list[Text], Field(min_length=1, max_length=1000)]


class InterpretationSelection(StrictModel):
    code: Code
    fact_ids: Annotated[list[Text], Field(max_length=1000)]
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False, strict=True)]


class StageSelection(StrictModel):
    stage_id: Text
    observed_facts: Annotated[list[FactSelection], Field(min_length=1, max_length=1000)]
    behavior_interpretation: InterpretationSelection
    potential_impact_codes: Annotated[list[Code], Field(max_length=10)]
    confirmed_impact: Annotated[list[FactSelection], Field(max_length=1000)]


class RelationSelection(StrictModel):
    relation_id: Text
    source_stage_id: Text
    target_stage_id: Text
    relation_type: Literal['DIRECTED_EDGE', 'UNDIRECTED_EDGE', 'STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED']
    direction_status: Literal['CONFIRMED_BY_ALGORITHM', 'UNRESOLVED']
    supporting_claim_ids: Annotated[list[Text], Field(max_length=1000)]


class SummarySelection(StrictModel):
    stage_ids: Annotated[list[Text], Field(min_length=1, max_length=1000)]
    main_fact_ids: Annotated[list[Text], Field(min_length=1, max_length=1000)]
    potential_impact_codes: Annotated[list[Code], Field(max_length=10)]
    confirmed_fact_ids: Annotated[list[Text], Field(max_length=1000)]


class StageExplanationDraft(StrictModel):
    chain_id: Text
    stages: Annotated[list[StageSelection], Field(min_length=1, max_length=1000)]
    relations: Annotated[list[RelationSelection], Field(max_length=10000)]
    chain_summary: SummarySelection


def preview_draft(context):
    """Deterministic validation fixture/preview; never labeled as model output."""
    p = context.data
    stages = []
    for item in p['stages']:
        facts = item['facts']
        codes = [c for c in item['eligible_codes'] if c != 'insufficient']
        priority = ['credential_file', 'server_shell', 'sql_pattern', 'traversal_pattern',
                    'process_execution', 'file_access', 'authentication', 'http_request', 'network']
        code = next((c for c in priority if c in codes), 'insufficient')
        stages.append(dict(stage_id=item['stage']['stage_id'],
            observed_facts=[dict(fact_id=f['fact_id'], evidence_refs=f['evidence_refs']) for f in facts],
            behavior_interpretation=dict(code=code,
                fact_ids=[f['fact_id'] for f in facts if code in f['eligible_codes']], confidence=0.0),
            potential_impact_codes=codes,
            confirmed_impact=[dict(fact_id=f['fact_id'], evidence_refs=f['evidence_refs']) for f in facts if f['confirmed']]))
    return dict(chain_id=p['chain']['chain_id'], stages=stages,
        relations=[{key: r[key] for key in ('relation_id', 'source_stage_id', 'target_stage_id',
                                          'relation_type', 'direction_status', 'supporting_claim_ids')} for r in p['relations']],
        chain_summary=dict(stage_ids=p['chain']['stage_ids'],
            main_fact_ids=[s['observed_facts'][0]['fact_id'] for s in stages],
            potential_impact_codes=sorted({c for s in stages for c in s['potential_impact_codes']}),
            confirmed_fact_ids=[f['fact_id'] for s in stages for f in s['confirmed_impact']]))


class StageExplanationService:
    def __init__(self, provider=None):
        self.provider = provider
        self.lock = Lock()
        self.cache = {}

    def explain(self, context):
        """No exception/draft can cross into pipeline state or reach the viewer."""
        envelope = dict(chain_id=context.data['chain']['chain_id'], input_digest=context.input_digest,
            contract_version=VERSION, read_only=True, status='unavailable',
            detail='AI 辅助研判暂不可用', grounding_status='pending', report_json=None, report_markdown=None,
            validation_errors=[], result_origin=None, generation_status='provider_unavailable')
        if self.provider is None:
            return envelope
        try:
            identity = (context.input_digest, self.provider.cache_identity, VERSION)
        except Exception:
            return dict(envelope, generation_status='provider_failed', validation_errors=['stage_ai_failed'])
        with self.lock:
            if identity in self.cache:
                return json.loads(self.cache[identity])
        try:
            raw = self.provider.explain(context)
            if not isinstance(raw, str) or len(raw.encode('utf-8')) > 2097152:
                raise ValueError('draft_size_invalid')
            # Reject duplicate keys (including aliases hiding a changed direction).
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate_json_key')
                    result[key] = value
                return result
            draft = StageExplanationDraft.model_validate(json.loads(raw, object_pairs_hook=unique))
            from .stage_grounding import validate_and_render
            report = validate_and_render(context, draft)
            envelope.update(status='available', detail='grounded_stage_explanation_ready',
                grounding_status='validated', report_json=report, report_markdown=markdown_report(report),
                result_origin='llm', generation_status='succeeded')
            # Bound process-local cache. Failures are retryable and never cached.
            with self.lock:
                if len(self.cache) >= 32:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[identity] = json.dumps(envelope, ensure_ascii=False)
        except ProviderError as exc:
            envelope.update(generation_status='provider_failed', validation_errors=[exc.code])
        except (ValidationError, json.JSONDecodeError, ValueError, TypeError, KeyError, RecursionError):
            envelope.update(grounding_status='rejected', generation_status='grounding_rejected',
                            validation_errors=['stage_draft_rejected'])
        except Exception:
            # Provider and sidecar bugs are isolated; do not echo raw responses,
            # secrets or exception text. Formal Chain retrieval is independent.
            envelope.update(generation_status='provider_failed', validation_errors=['stage_ai_failed'])
        return envelope


def markdown_report(report):
    """Export validated content as text; raw values cannot inject Markdown HTML."""
    from html import escape
    safe = lambda text: escape(str(text)).replace('`', '&#96;').replace('[', '&#91;').replace(']', '&#93;')
    lines = ['# Stage 辅助研判', '', safe(report['chain_id']), '', safe(report['chain_summary']['summary'])]
    for stage in report['stages']:
        lines.extend(['', '## ' + safe(stage['stage_id']), '', '### OBSERVED_FACT'])
        lines.extend('- ' + safe(f['description']) + ' [evidence: ' + safe(','.join(f['evidence_refs'])) + ']'
                     for f in stage['observed_facts'])
        lines.extend(['', '### BEHAVIOR_INTERPRETATION', safe(stage['behavior_interpretation']['description']),
                      '', '### MISSING_EVIDENCE', *['- ' + safe(v) for v in stage['missing_evidence']],
                      '', '### POTENTIAL_IMPACT', *['- ' + safe(v) for v in stage['risk_analysis']['potential_impact']],
                      '', '### CONFIRMED_IMPACT'])
        lines.extend('- ' + safe(v['description']) for v in stage['risk_analysis']['confirmed_impact'])
        if not stage['risk_analysis']['confirmed_impact']:
            lines.append('无证据支持的已确认后果。')
    lines.extend(['', '## 已有 Relation'])
    for r in report['relations']:
        lines.extend(['', safe(r['relation_id']) + ': ' + safe(r['relation_explanation']),
                      *['- ' + safe(v['description']) + ' [evidence: ' + safe(','.join(v['evidence_refs'])) + ']'
                        for v in r['supporting_evidence']], *['- ' + safe(v) for v in r['limitations']]])
    summary = report['chain_summary']
    for key in ('main_observed_activities', 'potential_overall_impact', 'confirmed_overall_impact', 'uncertainties'):
        lines.extend(['', '## ' + key])
        lines.extend('- ' + safe(v['description'] if isinstance(v, dict) else v) for v in summary[key])
    return '\n'.join(lines) + '\n'


class StageReportStore:
    """Sidecar-only storage; digest partition prevents stale report reuse."""
    def __init__(self, root):
        self.directory = Path(root) / 'outputs/ai_stage_reports'

    def path(self, context):
        # Content digest, never a client-controlled filename or chain path.
        return self.directory / (context.input_digest + '.json')

    def save(self, context, result):
        if result['status'] != 'available' or result['grounding_status'] != 'validated':
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        # UUID avoids collisions between concurrent requests/processes.
        from uuid import uuid4
        path = self.path(context)
        temp = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
        temp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        temp.replace(path)

    def read(self, context):
        """Re-ground persisted selections, never trust saved prose/status flags."""
        try:
            result = json.loads(self.path(context).read_text(encoding='utf-8'))
            if result['input_digest'] != context.input_digest or result['status'] != 'available':
                return None
            from .stage_grounding import validate_and_render
            draft = StageExplanationDraft.model_validate(result['report_json']['validated_selection'])
            report = validate_and_render(context, draft)
            if result['report_json'] != report or result['report_markdown'] != markdown_report(report):
                return None
            return dict(chain_id=report['chain_id'], input_digest=context.input_digest,
                contract_version=VERSION, read_only=True, status='available', detail='grounded_stage_explanation_ready',
                grounding_status='validated', report_json=report, report_markdown=markdown_report(report),
                validation_errors=[], result_origin='llm', generation_status='succeeded')
        except (OSError, ValueError, KeyError, TypeError):
            return None

"""Read-only Stage AI acceptance, adversarial grounding and failure isolation."""
import copy
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.ai.provider import LLMProvider, ProviderConfig, ProviderError
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.ai.stage_context import StageContext, build_stage_context
from app.ai.stage_explanation import (StageExplanationDraft, StageExplanationService, StageReportStore,
                                      preview_draft, markdown_report)
from app.ai.stage_grounding import validate_and_render
from app.ai.stage_knowledge import make_stage_evidence
from app.evidence_trace.snapshot import file_sha256
from app.models.base import resolve_pointer
from app.services.queries import QueryError
from app.stage_chains.stage9_reader import Stage9ArtifactReader

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / 'outputs/attack125_final_rerun_20261023_measured'


class DraftProvider(LLMProvider):
    name, model = 'test_double', 'not-a-real-model'

    def __init__(self, mutate=None, failure=None):
        self.mutate, self.failure, self.calls = mutate, failure, 0

    def explain(self, context):
        self.calls += 1
        if self.failure:
            raise self.failure
        draft = preview_draft(context)
        if self.mutate:
            self.mutate(draft)
        return json.dumps(draft)


def synthetic_context(raw=None, second=True, kind='UNDIRECTED_EDGE', rejected=False):
    raws = [raw or dict(hostname='web-1', user='www-data', operation='ProcessStart', process_name='sh',
                parent_process_name='nginx', command_line='/bin/sh /srv/uploads/test.cgi')]
    if second:
        raws.append(dict(hostname='web-1', operation='NetworkConnection', process_name='sh',
                         src_ip='10.0.0.1', dst_ip='10.0.0.2', dst_port=443))
    stages, alerts = [], {}
    for i, record in enumerate(raws):
        aid, sid = f'alt_{i}', f'stg_{i}'
        alert = dict(alert_id=aid, raw_alert=record)
        stage = dict(stage_id=sid, alert_ids=[aid], behavior='EXECUTION')
        stages.append(dict(stage=stage, alerts=[alert], **make_stage_evidence(stage, [alert])))
        alerts[aid] = alert
    relations, claims, obs, pointers = [], {}, {}, {}
    if second and not rejected:
        directed = kind != 'UNDIRECTED_EDGE'
        claims['claim_1'] = dict(claim_id='claim_1', valid=True, stage_a_id='stg_0', stage_b_id='stg_1',
            evidence_type='TEMPORAL_PROXIMITY' if kind == 'WEAK_DIRECTED' else 'SAME_PROCESS_INSTANCE',
            reason='existing evidence', observation_ids=['obs_1'])
        obs['obs_1'] = dict(alert_a_id='alt_0', alert_b_id='alt_1', raw_pointer_ids=['ptr_1'])
        pointers['ptr_1'] = dict(raw_pointer=dict(alert_id='alt_0', pointer='/hostname'), value=raws[0]['hostname'])
        relations.append(dict(relation_id='rel_1', accepted=True, source_stage_id='stg_0', target_stage_id='stg_1',
            relation_type=kind, direction_status='CONFIRMED_BY_ALGORITHM' if directed else 'UNRESOLVED',
            supporting_claim_ids=['claim_1'], required_claim_ids=['claim_1'],
            decision=dict(stage_a_id='stg_0', stage_b_id='stg_1')))
    package = dict(chain=dict(chain_id='chain_1', stage_ids=[s['stage']['stage_id'] for s in stages],
                    relation_ids=[r['relation_id'] for r in relations], has_directed_cycle=False),
        stages=stages, relations=relations, claims=claims, observations=obs, resolved_pointers=pointers,
        independent_chain_count=3, rejected_decisions=[dict(relation_type='NO_RELATION')] if rejected else [])
    return StageContext(json.dumps(package), 'a'*64)


@pytest.fixture(scope='module')
def real_context():
    if not (ARTIFACT / 'stage9.json').is_file():
        pytest.skip('official ATTACK125 sealed artifact is local-only')
    reader = Stage9ArtifactReader(ROOT, ARTIFACT)
    chain = max(reader.load()['reconstruction'].chains, key=lambda c: len(c.stage_ids))
    return build_stage_context(reader, chain.chain_id)


def test_real_adapter_reads_formal_members_alerts_relations_and_grounded_preview(real_context):
    context = real_context
    p = context.data
    assert len(p['stages']) == 9 and len(p['relations']) == 12
    assert sum(r['direction_status'] == 'UNRESOLVED' for r in p['relations']) == 3
    assert p['bindings'] and p['entities'] and p['claims'] and p['resolved_pointers']
    assert len(context.model_payload.encode()) < 524288
    assert all('raw_alert' in a for s in p['stages'] for a in s['alerts'])
    report = validate_and_render(context, StageExplanationDraft.model_validate(preview_draft(context)))
    assert len(report['chain_summary']['topology']['branches']) == 2
    assert len(report['chain_summary']['topology']['merges']) == 3
    assert '严格线性' in report['chain_summary']['summary']
    raw = {a['alert_id']: a['raw_alert'] for s in p['stages'] for a in s['alerts']}
    for stage in report['stages']:
        for fact in stage['observed_facts'] + stage['risk_analysis']['confirmed_impact']:
            assert fact['evidence_refs'] and set(fact['evidence_refs']) <= raw.keys()
            for ref in fact['field_refs']:
                assert resolve_pointer(raw[ref['alert_id']], ref['pointer']) == ref['value']
    assert any('cat /var/lib/backup/.ssh/id_ed25519' in f['description']
               for s in report['stages'] for f in s['observed_facts'])
    assert all(file_sha256(path) == digest for path, digest in p['artifact_sha256'].items())


@pytest.mark.parametrize('mutation', [
    lambda d: d['stages'][0]['observed_facts'][0]['evidence_refs'].append('alt_nonexistent'),
    lambda d: d['stages'][0]['observed_facts'][0].update(fact_id='fact_alt_nonexistent'),
    lambda d: d['stages'][0]['observed_facts'][0].update(evidence_refs=['alt_1']),
    lambda d: d['stages'][0]['observed_facts'].append(d['stages'][1]['observed_facts'][0]),
    lambda d: d['stages'].pop(),
    lambda d: d['stages'].append(copy.deepcopy(d['stages'][0])),
    lambda d: d.update(chain_id='other_chain'),
    lambda d: d['relations'][0].update(direction_status='CONFIRMED_BY_ALGORITHM'),
    lambda d: d['relations'][0].update(relation_type='DIRECTED_EDGE'),
    lambda d: d['relations'][0].update(source_stage_id='stg_1', target_stage_id='stg_0'),
    lambda d: d['relations'].append(copy.deepcopy(d['relations'][0])),
    lambda d: d['relations'].clear(),
    lambda d: d['relations'][0].update(supporting_claim_ids=['fake_claim']),
    lambda d: d['relations'][0].update(supporting_claim_ids=[]),
    lambda d: d['stages'][0]['behavior_interpretation'].update(description='数据已经泄露'),
    lambda d: d['stages'][0]['observed_facts'][0].update(description='服务器已经失陷'),
    lambda d: d['stages'][0]['confirmed_impact'].append(dict(fact_id='fact_alt_0', evidence_refs=['alt_0'])),
    lambda d: d['stages'][0]['confirmed_impact'].append('数据已经泄露'),
    lambda d: d['stages'][0]['behavior_interpretation'].update(code='credential_file'),
    lambda d: d['stages'][0].update(potential_impact_codes=['credential_file']),
    lambda d: d['chain_summary'].update(summary='A 之后进入 B，服务器已经失陷'),
    lambda d: d['chain_summary']['confirmed_fact_ids'].append('fact_alt_0'),
    lambda d: d['chain_summary']['stage_ids'].pop(),
    lambda d: d['chain_summary']['main_fact_ids'].append('fact_unknown'),
    lambda d: d['stages'][0]['behavior_interpretation'].update(confidence=True),
    lambda d: d['stages'][0]['behavior_interpretation'].update(confidence=float('nan')),
])
def test_adversarial_drafts_rejected_without_publishing_any_text(mutation):
    ctx = synthetic_context()
    before = ctx.payload
    result = StageExplanationService(DraftProvider(mutation)).explain(ctx)
    assert result['status'] == 'unavailable' and result['grounding_status'] == 'rejected'
    assert result['report_json'] is None and result['report_markdown'] is None
    assert result['detail'] == 'AI 辅助研判暂不可用'
    assert before == ctx.payload


def test_auth_failure_cannot_be_promoted_to_account_compromise():
    ctx = synthetic_context(dict(hostname='auth-1', operation='authentication_failure', account='admin', result='failure'), second=False)
    result = StageExplanationService(DraftProvider()).explain(ctx)
    assert result['status'] == 'available'
    s = result['report_json']['stages'][0]
    assert s['risk_analysis']['confirmed_impact'] == []
    assert any('没有明确的成功认证证据' in m for m in s['missing_evidence'])
    fake = lambda d: d['stages'][0]['confirmed_impact'].append(dict(fact_id='fact_alt_0', evidence_refs=['alt_0']))
    assert StageExplanationService(DraftProvider(fake)).explain(ctx)['grounding_status'] == 'rejected'


def test_auth_success_confirms_only_authentication_and_file_failure_confirms_nothing():
    ctx = synthetic_context(dict(hostname='auth-1', operation='credential_accepted', account='admin', result='success'), second=False)
    r = StageExplanationService(DraftProvider()).explain(ctx)['report_json']
    assert '不证明账户已失陷' in r['stages'][0]['risk_analysis']['confirmed_impact'][0]['description']
    ctx = synthetic_context(dict(hostname='web-1', operation='FileCreate', file_path='/tmp/a', result='failed'), second=False)
    assert not StageExplanationService(DraftProvider()).explain(ctx)['report_json']['stages'][0]['risk_analysis']['confirmed_impact']


def test_temporal_only_relation_is_never_causal_and_rejection_never_becomes_an_edge():
    ctx = synthetic_context(kind='WEAK_DIRECTED')
    report = StageExplanationService(DraftProvider()).explain(ctx)['report_json']
    assert '无法据此确认攻击因果' in report['relations'][0]['relation_explanation']
    assert not report['chain_summary']['topology']['branches']
    mut = lambda d: d['relations'][0].update(relation_explanation='A 导致 B，因为时间接近')
    assert StageExplanationService(DraftProvider(mut)).explain(ctx)['grounding_status'] == 'rejected'
    rejected = synthetic_context(rejected=True)
    add_edge = lambda d: d['relations'].append(preview_draft(ctx)['relations'][0])
    assert StageExplanationService(DraftProvider(add_edge)).explain(rejected)['grounding_status'] == 'rejected'


def test_directed_keeps_formal_direction_even_when_reverse_to_stage_order():
    ctx = synthetic_context(kind='DIRECTED_EDGE')
    p = ctx.data
    p['relations'][0].update(source_stage_id='stg_1', target_stage_id='stg_0')
    ctx = StageContext(json.dumps(p), 'b'*64)
    report = StageExplanationService(DraftProvider()).explain(ctx)['report_json']
    assert report['relations'][0]['source_stage_id'] == 'stg_1'
    assert 'stg_1 → stg_0' in report['relations'][0]['relation_explanation']


def test_singleton_sparse_and_command_intent_do_not_invent_actions():
    ctx = synthetic_context(dict(hostname='web-1', process_name='powershell.exe', operation='ProcessStart'), second=False)
    report = StageExplanationService(DraftProvider()).explain(ctx)['report_json']
    assert '单节点' in report['chain_summary']['summary'] and not report['relations']
    assert any('command_line' in text for text in report['stages'][0]['missing_evidence'])
    ctx = synthetic_context(dict(hostname='web-1', command_line='cat /etc/shadow', operation='NetworkConnection'), second=False)
    assert 'credential_file' not in ctx.data['stages'][0]['eligible_codes']
    assert not ctx.data['stages'][0]['confirmed_fact_ids']


def test_storage_revalidates_tampering_and_digest_and_escapes_raw_markup(tmp_path):
    ctx = synthetic_context(dict(hostname='web-1', operation='ProcessStart', command_line='<script>alert(1)</script> [x](https://bad.invalid)'), second=False)
    result = StageExplanationService(DraftProvider()).explain(ctx)
    assert '<script>' not in result['report_markdown'] and '&#91;' in result['report_markdown']
    store = StageReportStore(tmp_path)
    store.save(ctx, result)
    assert store.read(ctx)['report_json'] == result['report_json']
    edited = copy.deepcopy(result)
    edited['report_json']['stages'][0]['observed_facts'][0]['description'] = '数据已泄露'
    store.path(ctx).write_text(json.dumps(edited))
    assert store.read(ctx) is None
    assert store.read(StageContext(ctx.payload, 'c'*64)) is None


@pytest.mark.parametrize('error', [ProviderError('provider_timeout'), RuntimeError('secret response'), ValueError('bad body')])
def test_provider_failures_are_contained_and_never_echo_exceptions(error):
    result = StageExplanationService(DraftProvider(failure=error)).explain(synthetic_context())
    assert result['status'] == 'unavailable' and result['report_json'] is None
    assert 'secret' not in json.dumps(result)
    assert StageExplanationService().explain(synthetic_context())['generation_status'] == 'provider_unavailable'


def test_transport_uses_stage_schema_and_bounded_context_without_legacy_incident_prompt():
    ctx = synthetic_context()
    cfg = ProviderConfig(base_url='https://example.invalid/v1', model='test', api_key='unused')
    def handler(req):
        body = json.loads(req.content)
        prompt = body['messages'][1]['content']
        assert 'evidence_package' in prompt and 'StageExplanationDraft' in prompt
        assert 'IncidentID' not in prompt and 'action_templates' not in prompt
        return httpx.Response(200, json=dict(choices=[dict(message=dict(content=json.dumps(preview_draft(ctx))), finish_reason='stop')]))
    provider = OpenAICompatibleProvider(cfg, transport=httpx.MockTransport(handler))
    assert StageExplanationService(provider).explain(ctx)['status'] == 'available'


def test_cache_is_partitioned_and_returns_detached_reports():
    ctx = synthetic_context()
    provider = DraftProvider()
    service = StageExplanationService(provider)
    first = service.explain(ctx)
    first['report_json']['stages'].clear()
    assert service.explain(ctx)['report_json']['stages'] and provider.calls == 1
    assert service.explain(StageContext(ctx.payload, 'd'*64))['status'] == 'available' and provider.calls == 2


def test_cycle_isolated_stages_and_multiple_chains_are_retained():
    ctx = synthetic_context(rejected=True)
    p = ctx.data
    p['chain']['has_directed_cycle'] = True
    ctx = StageContext(json.dumps(p), 'e'*64)
    result = StageExplanationService(DraftProvider()).explain(ctx)
    report = result['report_json']
    assert len(report['stages']) == 2 and report['relations'] == []
    assert set(report['chain_summary']['topology']['isolated_stage_ids']) == {'stg_0', 'stg_1'}
    assert '不能描述成严格先后步骤' in report['chain_summary']['summary']
    assert '3 条独立 Chain，未合并' in report['chain_summary']['summary']


def test_raw_value_mismatch_is_rejected_instead_of_trusting_fact_catalog():
    ctx = synthetic_context()
    p = ctx.data
    p['stages'][0]['alerts'][0]['raw_alert']['command_line'] = 'different raw value'
    altered = StageContext(json.dumps(p), 'f'*64)
    assert StageExplanationService(DraftProvider()).explain(altered)['grounding_status'] == 'rejected'


def test_real_single_stage_chain_retains_original_members_and_zero_edges():
    if not (ARTIFACT / 'stage9.json').is_file():
        pytest.skip('official local artifact unavailable')
    reader = Stage9ArtifactReader(ROOT, ARTIFACT)
    chain = next(c for c in reader.load()['reconstruction'].chains if c.single_stage)
    ctx = build_stage_context(reader, chain.chain_id)
    result = StageExplanationService(DraftProvider()).explain(ctx)
    assert result['status'] == 'available'
    assert [s['stage_id'] for s in result['report_json']['stages']] == chain.stage_ids
    assert result['report_json']['relations'] == []


def test_api_primary_chain_failure_keeps_chain_relations_alerts_and_rejects_legacy(real_context, tmp_path, monkeypatch):
    from app.api.stage_workbench import install_stage_workbench, STAGE9_ANALYSIS_ID, StageWorkbench
    monkeypatch.setattr(StageWorkbench, 'stage9_reader', lambda self: Stage9ArtifactReader(ROOT, ARTIFACT))
    import app.stage_chains.reconstruction as reconstruction
    monkeypatch.setattr(reconstruction, 'reconstruct_attack_chains', lambda *a, **kw: pytest.fail('algorithm replay'))
    app = FastAPI()
    @app.exception_handler(QueryError)
    async def error(request: Request, exc: QueryError):
        return JSONResponse(status_code=exc.status, content=dict(detail=exc.code))
    install_stage_workbench(app, tmp_path)
    base = '/api/v1/stage-analyses/' + STAGE9_ANALYSIS_ID
    route = base + '/chains/' + real_context.data['chain']['chain_id']
    app.state.stage_explanations = StageExplanationService(DraftProvider(failure=ProviderError('provider_timeout')))
    with TestClient(app) as client:
        original = client.get(base).json()
        assert client.get(route + '/explanation').json()['result'] is None
        package = client.get(route + '/ai-evidence').json()['evidence_package']
        assert len(package['stages']) == 9
        assert client.post(route + '/explain').json()['status'] == 'unavailable'
        assert client.get(base).json() == original
        aid = real_context.data['stages'][0]['alerts'][0]['alert_id']
        assert client.get(base + '/alerts/' + aid).json()['raw_alert']
        assert client.get(base + '/traces/' + original['relations'][0]['relation_id']).status_code == 200
        assert client.post('/api/v1/stage-analyses/ana_' + '0'*64 + '/chains/x/explain').status_code == 404
        assert client.post(base + '/chains/missing/explain').status_code == 404
        assert client.get(route + '/ai-evidence?labels=forbidden').status_code == 400
        app.state.stage_explanations = StageExplanationService(DraftProvider())
        result = client.post(route + '/explain').json()
        assert result['status'] == 'available'
        saved = client.get(route + '/explanation').json()['result']
        assert saved['report_json'] == result['report_json']
        assert saved['analysis_id'] == STAGE9_ANALYSIS_ID
        assert client.get(base).json() == original
    assert all(file_sha256(p) == h for p, h in real_context.data['artifact_sha256'].items())

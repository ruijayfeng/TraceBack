"""Task 07.1 service/API integration and read-only real snapshot smoke."""

import builtins
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import socket

from fastapi.testclient import TestClient
from fastapi import FastAPI
import pytest

from app.ai.explanation import ExplanationService, build_context, load_context
from app.ai.providers.fake import FakeProvider, valid_draft
from app.chains.assembly import run_reconstruction
from app.config import load_config
from app.main import create_app
from app.services.queries import QueryService
from app.services.storage import file_digest
from app.utils.stable_id import content_digest, id_for
from fixtures.chains.synthetic import linear_fixture
from test_analysis_service import deployment, edge_records, request_for, tripwire, write_input
from test_correlation_score import alert, inputs
from test_wazuh_adapter import ROOT, synthetic_record


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    connect = socket.socket.connect
    def forbidden(sock, address):
        # Windows asyncio constructs its socketpair through loopback TCP.
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
            return connect(sock, address)
        raise AssertionError("AI tests must never connect to an external provider")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    for name in ("TRACEBACK_LLM_BASE_URL", "TRACEBACK_LLM_MODEL", "TRACEBACK_LLM_API_KEY", "TRACEBACK_LLM_TIMEOUT_SECONDS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def algorithm():
    return load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml")


@pytest.fixture
def chain_source(algorithm):
    index, settings, values, correlation = linear_fixture(algorithm)
    result = run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), correlation.edges,
                                algorithm, settings, upstream_record=correlation.record)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    incident = next(i for i in result.incidents if i.incident_id == chain.incident_id)
    return result.record.analysis_id, incident, chain, index, correlation, values


def context_from(source, **options):
    analysis_id, incident, chain, index, correlation, _ = source
    return build_context(analysis_id, incident, chain, [index.alerts[a] for a in incident.alert_ids],
                         [index.entities[e] for e in incident.entity_ids],
                         [e for e in correlation.edges if e.edge_id in incident.correlation_edge_ids], **options)


@pytest.fixture
def chain_context(chain_source):
    return context_from(chain_source)


@pytest.fixture
def singleton_context(algorithm):
    index, settings = inputs([alert("synthetic-singleton", category="unknown", host="synthetic-singleton-host")])
    result = run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), [], algorithm, settings)
    return build_context(result.record.analysis_id, result.incidents[0], result.chains[0], list(index.alerts.values()),
                         list(index.entities.values()), [])


@pytest.fixture
def shell_singleton_context(algorithm):
    index, settings = inputs([alert("synthetic-shell", category="command_execution", host="synthetic-shell-host",
                                   command="/bin/sh -c id")])
    result = run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), [], algorithm, settings)
    return build_context(result.record.analysis_id, result.incidents[0], result.chains[0], list(index.alerts.values()),
                         list(index.entities.values()), [])


@pytest.fixture
def shell_chain_source(algorithm, monkeypatch):
    # Reuse the accepted A -> B -> C fixture, adding an observed command to B.
    # This changes synthetic input, never production mapping or graph rules.
    import fixtures.chains.synthetic as synthetic
    original = synthetic.alert
    def shell_alert(name, *args, **kwargs):
        if name == "synthetic-B":
            kwargs["command"] = "/bin/sh -c id"
        return original(name, *args, **kwargs)
    monkeypatch.setattr(synthetic, "alert", shell_alert)
    index, settings, values, correlation = linear_fixture(algorithm)
    result = run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), correlation.edges,
                                algorithm, settings, upstream_record=correlation.record)
    chain = next(c for c in result.chains if len(c.nodes) == 3)
    incident = next(i for i in result.incidents if i.incident_id == chain.incident_id)
    return result.record.analysis_id, incident, chain, index, correlation, values


@pytest.fixture
def shell_chain_context(shell_chain_source):
    return context_from(shell_chain_source)


def test_context_exact_projection_and_deep_immutability(chain_context):
    data = chain_context.data
    assert len(data["facts"]["nodes"]) == 3 and len(data["facts"]["edges"]) == 2
    assert data["ordered_edge_ids"] and data["evidence_refs"]
    assert len(data["fact_options"]["progression"]) == 2
    assert all("raw_alert" not in a and "signature" not in a and "command" not in a for a in data["facts"]["alerts"].values())
    assert "diagnostics" not in data and "summary" not in data["incident"]
    assert all(e["reasons"] and e["score_breakdown"] for e in data["facts"]["edges"].values())
    data["facts"]["nodes"].clear()
    assert len(chain_context.data["facts"]["nodes"]) == 3
    with pytest.raises(FrozenInstanceError):
        chain_context.payload = "changed"


def test_digest_reordering_versions_and_fact_changes(chain_source):
    original = context_from(chain_source)
    aid, inc, chain, index, correlation, _ = chain_source
    reversed_context = build_context(aid, inc, chain, list(reversed([index.alerts[a] for a in inc.alert_ids])),
                                    list(reversed([index.entities[e] for e in inc.entity_ids])),
                                    list(reversed([e for e in correlation.edges if e.edge_id in inc.correlation_edge_ids])))
    assert reversed_context == original
    assert context_from(chain_source, template_version="new-template").input_digest != original.input_digest
    assert context_from(chain_source, grounding_version="new-validator").input_digest != original.input_digest
    assert context_from(chain_source, is_complete=False).input_digest != original.input_digest
    changed = chain.model_copy(update={"status": "partial"})
    assert build_context(aid, inc, changed, [index.alerts[a] for a in inc.alert_ids],
                         [index.entities[e] for e in inc.entity_ids],
                         [e for e in correlation.edges if e.edge_id in inc.correlation_edge_ids]).input_digest != original.input_digest


def test_singleton_explanation_first_class(singleton_context):
    result = ExplanationService(FakeProvider()).explain(singleton_context)
    assert result.status == "available" and result.grounding_status == "validated"
    assert not result.attack_progression
    assert {u.code for u in result.uncertainties} >= {"singleton_incident", "insufficient_relation", "alerts_not_confirmed_attack"}
    assert result.summary and result.key_findings and result.recommended_actions
    assert all(c.grounding_status.value == "validated" for c in result.explanation.claims)
    assert result.explanation.explanation_id == id_for("AIExplanation", result.explanation)


def test_fixture_a_b_c_explanation_and_algorithm_unchanged(chain_context, chain_source):
    before = content_digest([obj.model_dump(mode="json") for obj in [chain_source[1], chain_source[2], *chain_source[3].alerts.values()]])
    result = ExplanationService(FakeProvider()).explain(chain_context)
    assert result.status == "available", result.validation_errors
    assert [p.step for p in result.attack_progression] == [1, 2]
    owner = {aid: n.node_id for n in chain_source[2].nodes for aid in n.alert_ids}
    expected = [(owner[chain_source[5][i].alert_id], owner[chain_source[5][i + 1].alert_id]) for i in range(2)]
    actual = []
    for p in result.attack_progression:
        fields = {v.field: v.value for v in p.propositions}
        actual.append((fields["source_node_id"], fields["target_node_id"]))
        assert p.evidence_refs and "PROCESS_CAUSAL" in p.statement
    assert actual == expected
    assert before == content_digest([obj.model_dump(mode="json") for obj in [chain_source[1], chain_source[2], *chain_source[3].alerts.values()]])


@pytest.mark.parametrize("mode,status,detail", [
    ("timeout", "unavailable", "provider_timeout"),
    ("invalid_json", "validation_failed", "provider_invalid_draft"),
    ("empty", "validation_failed", "provider_invalid_draft"),
    ("missing_field", "validation_failed", "provider_invalid_draft"),
    ("invalid_evidence", "available", "grounding_partial_rejection"),
    ("invalid_node", "available", "grounding_partial_rejection"),
])
def test_fake_failures_never_publish(singleton_context, mode, status, detail):
    result = ExplanationService(FakeProvider(mode)).explain(singleton_context)
    assert result.status == status and result.detail == detail
    assert result.degraded and result.grounding_status == "validated"
    assert result.summary and result.report_json and result.report_markdown and not result.attack_progression
    assert all(c.grounding_status.value == "validated" for c in result.explanation.claims)
    assert not result.attack_techniques


def test_provider_unconfigured_context_still_ready(singleton_context):
    result = ExplanationService().explain(singleton_context)
    assert result.status == "unavailable" and result.detail == "provider_not_configured"
    assert result.context_status == "context_ready" and result.result_origin == "deterministic"
    assert result.explanation and result.report_json and result.degraded


def test_cache_boundaries_and_return_mutation(chain_context):
    provider = FakeProvider()
    service = ExplanationService(provider, cache_size=1)
    first = service.explain(chain_context)
    first.summary.clear()
    second = service.explain(chain_context)
    assert provider.calls == 1 and second.summary
    provider.model = "different-model"
    changed = service.explain(chain_context)
    assert provider.calls == 2 and changed.explanation.explanation_id != second.explanation.explanation_id
    provider.name = "different-provider"
    service.explain(chain_context)
    assert provider.calls == 3
    assert len(service._cache) == 1


def test_shared_entity_does_not_leak_other_incident_alert_ids(algorithm):
    index, settings = inputs([alert("singleton-one", host="same-synthetic-host"),
                              alert("singleton-two", 5, host="same-synthetic-host")])
    result = run_reconstruction(list(index.alerts.values()), [], list(index.entities.values()), [], algorithm, settings)
    incident = result.incidents[0]
    chain = next(c for c in result.chains if c.incident_id == incident.incident_id)
    context = build_context(result.record.analysis_id, incident, chain, [index.alerts[a] for a in incident.alert_ids],
                            [index.entities[e] for e in incident.entity_ids], [])
    foreign = (set(index.alerts) - set(incident.alert_ids)).pop()
    assert foreign not in context.payload
    assert all(e["alert_ids"] == incident.alert_ids for e in context.data["facts"]["entities"].values())


@pytest.fixture
def explain_api(tmp_path):
    config, sources = deployment(tmp_path, edge=True)
    app = create_app(tmp_path, configs={"v0": config}, sources=sources)
    path = write_input(tmp_path, edge_records())
    aid = app.state.analyses.create(request_for(path), background=False)
    iid = app.state.queries.list(aid, "incidents", page=1, page_size=20, filters={})["items"][0].incident_id
    with TestClient(app) as client:
        yield client, app, aid, iid


@pytest.mark.parametrize("mode,expected", [("valid", 200), (None, 409), ("timeout", 409), ("invalid_evidence", 200)])
def test_api_service_outcomes_and_queries_survive(explain_api, mode, expected):
    client, app, aid, iid = explain_api
    app.state.explanations = ExplanationService(FakeProvider(mode) if mode else None)
    scope = {"analysis_id": aid}
    before = client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json()
    response = client.post(f"/api/v1/incidents/{iid}/explain", params=scope, json={})
    assert response.status_code == expected, response.text
    result = response.json()
    assert result["status"] == ("available" if mode in {"valid", "invalid_evidence"} else "unavailable")
    assert result["context_status"] == "context_ready"
    assert client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json() == before
    assert client.get(f"/api/v1/incidents/{iid}", params=scope).status_code == 200
    assert client.get("/api/v1/alerts/" + before["chain"]["nodes"][0]["alert_ids"][0], params=scope).status_code == 200


def test_api_not_found_invalid_input_and_single_registration(explain_api):
    client, app, aid, iid = explain_api
    assert client.post("/api/v1/incidents/inc_" + "f" * 64 + "/explain", params={"analysis_id": aid}).status_code == 404
    assert client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid}, json={"ground_truth": True}).status_code == 422
    assert client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid, "provider": "fake"}).status_code == 400
    assert sum(getattr(r, "path", "").endswith("/explain") for r in app.routes) == 1
    success = client.get("/openapi.json").json()["paths"]["/api/v1/incidents/{incident_id}/explain"]["post"]["responses"]["200"]
    assert success["content"]["application/json"]["schema"]["$ref"].endswith("GroundedExplanation")


def test_singleton_api_http_provider_end_to_end(tmp_path):
    import httpx
    from app.ai.provider import ProviderConfig
    from app.ai.providers.openai_compatible import OpenAICompatibleProvider
    from app.ai.providers.fake import valid_draft
    from pydantic import SecretStr
    config, sources = deployment(tmp_path)
    app = create_app(tmp_path, configs={"v0": config}, sources=sources)
    path = write_input(tmp_path, [synthetic_record()])
    aid = app.state.analyses.create(request_for(path), background=False)
    iid = app.state.queries.list(aid, "incidents", page=1, page_size=20, filters={})["items"][0].incident_id
    context = load_context(app.state.queries, aid, iid)
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"choices": [{"message": {
        "content": json.dumps(valid_draft(context), ensure_ascii=False)}, "finish_reason": "stop"}]}))
    provider = OpenAICompatibleProvider(ProviderConfig(base_url="https://provider.invalid/v1", model="fixture-model",
        api_key=SecretStr("fixture-placeholder")), transport=transport)
    app.state.explanations = ExplanationService(provider)
    with TestClient(app) as client:
        response = client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    assert response.status_code == 200, response.text
    assert response.json()["grounding_status"] == "validated" and not response.json()["attack_progression"]
    assert response.json()["provider_metadata"]["provider"] == "openai_compatible"
    assert "fixture-placeholder" not in response.text


def test_invalid_provider_configuration_graceful(explain_api, monkeypatch):
    client, app, aid, iid = explain_api
    monkeypatch.setenv("TRACEBACK_LLM_BASE_URL", "invalid-url")
    response = client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    assert response.status_code == 409 and response.json()["detail"] == "provider_configuration_invalid"
    assert client.get(f"/api/v1/incidents/{iid}/chain", params={"analysis_id": aid}).status_code == 200


def test_api_gt_tripwire_and_no_discovery(explain_api, monkeypatch):
    client, app, aid, iid = explain_api
    reads = tripwire(monkeypatch)
    app.state.explanations = ExplanationService(FakeProvider())
    def forbidden(*args, **kwargs):
        raise AssertionError("Explain must never run discovery or reconstruction")
    import app.services.analysis as analysis
    for name in ("deduplicate", "extract_entities", "run_correlation", "run_reconstruction"):
        monkeypatch.setattr(analysis, name, forbidden)
    response = client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    assert response.status_code == 200, response.text
    assert reads


def test_real_russellmitchell_singleton_smoke(monkeypatch):
    """Read an existing production snapshot; never recompute/tune or read GT."""
    reads = tripwire(monkeypatch)
    q = QueryService(ROOT)
    candidates = []
    for path in sorted((ROOT / "data/processed").glob("ana_*/run.json")):
        run = json.loads(path.read_text(encoding="utf-8"))
        namespaces = {v.get("source_namespace") for v in run.get("input_files", [])}
        if (run.get("status") == "completed" and run.get("config_version") == "v0" and run.get("candidate_contract_version") == "v1.1"
                and "ait_ads.russellmitchell.wazuh" in namespaces and "ait_ads.russellmitchell.aminer" in namespaces):
            candidates.append(run)
    assert candidates, "required real production baseline missing"
    run = max(candidates, key=lambda r: (r["created_at"], r["analysis_id"]))
    aid = run["analysis_id"]
    assert run["counts"]["chain_edge_count"] == run["counts"]["correlation_edge_count"] == 0
    folder = ROOT / "data/processed" / aid
    paths = [*(folder.glob("*")), ROOT / "outputs/analyses" / aid / "manifest.json"]
    before = {str(p): file_digest(p) for p in paths if p.is_file()}
    page = q.list(aid, "incidents", page=1, page_size=100, filters={})
    incident = next(i for i in page["items"] if len(i.alert_ids) == 1)
    context = load_context(q, aid, incident.incident_id)
    unavailable = ExplanationService().explain(context)
    assert unavailable.context_status == "context_ready" and unavailable.detail == "provider_not_configured"
    data = context.data
    assert len(data["facts"]["nodes"]) == 1 and not data["facts"]["edges"]
    assert data["evidence_refs"] and not data["ordered_edge_ids"]
    # Exercise the actual registered endpoint on a read-only test host. Do not
    # start production lifespan jobs or an AnalysisService against real data.
    from app.api.routes import router
    api_app = FastAPI()
    api_app.state.queries = q
    api_app.include_router(router)
    with TestClient(api_app) as client:
        response = client.post(f"/api/v1/incidents/{incident.incident_id}/explain", params={"analysis_id": aid})
    assert response.status_code == 409 and response.json()["detail"] == "provider_not_configured"
    assert response.json()["context_status"] == "context_ready"
    # Separate explicit offline grounding probe; never presented as real LLM.
    grounded = ExplanationService(FakeProvider()).explain(context)
    assert grounded.status == "available", grounded.validation_errors
    assert not grounded.attack_progression and not grounded.explanation.claims[0].edge_ids
    assert before == {str(p): file_digest(p) for p in paths if p.is_file()}
    assert not any("evaluation" in p.lower() or "labels.csv" in p.lower() for p in reads)
    print(json.dumps({"analysis_id": aid, "incident_id": incident.incident_id, "alert_ids": incident.alert_ids,
                      "input_digest": context.input_digest, "context_status": "context_ready",
                      "provider_status": unavailable.detail, "offline_grounding_probe": grounded.status,
                      "nodes": 1, "edges": 0, "evidence_ref_count": len(data["evidence_refs"]),
                      "production_snapshot_unchanged": True}, ensure_ascii=False))


def test_task072_shell_singleton_and_full_soc_output(shell_singleton_context):
    from app.ai.report import json_report, markdown_report
    result = ExplanationService(FakeProvider()).explain(shell_singleton_context)
    assert result.status == "available", result.validation_errors
    assert {m.technique_id for m in result.attack_techniques} == {"T1059", "T1059.004"}
    assert result.summary and result.assessment and result.key_entities and result.risk and result.recommended_actions
    assert not result.attack_progression
    assert result.risk.confidence == "not_calibrated"
    assert all(m.confidence == "tentative" for m in result.attack_techniques)
    assert json_report(result.explanation)["grounding_status"] == "validated"
    assert markdown_report(result.explanation, soc=result.report_json) == result.report_markdown
    assert "T1059.004" in result.report_markdown
    assert result.explanation.explanation_id == id_for("AIExplanation", result.explanation)
    assert all(c.claim_id == id_for("AIClaim", c) for c in result.explanation.claims)


def test_task072_chain_mapping_fact_object_evidence_closure(shell_chain_context, shell_chain_source):
    objects = [shell_chain_source[1], shell_chain_source[2], *shell_chain_source[3].alerts.values(),
               *shell_chain_source[3].entities.values(), *shell_chain_source[4].edges]
    before = content_digest([o.model_dump(mode="json") for o in objects])
    result = ExplanationService(FakeProvider()).explain(shell_chain_context)
    assert result.status == "available"
    assert len(shell_chain_source[2].nodes) == 3 and len(shell_chain_source[2].edges) == 2
    assert len(result.attack_techniques) == 2 and len(result.attack_progression) == 2
    claims = {c.claim_id: c for c in result.explanation.claims}
    facts = {f.claim_id: f for f in result.key_findings}
    for mapping in result.attack_techniques:
        assert mapping.mapping_status == "validated"
        for fid in mapping.supporting_fact_ids:
            fact = facts[fid]
            assert claims[fid].kind.value == "fact"
            assert mapping.object_refs == fact.object_refs
            assert mapping.node_refs == fact.node_refs and mapping.alert_refs == fact.alert_refs
            assert mapping.evidence_refs == fact.evidence_refs
        assert claims[mapping.claim_id].kind.value == "attack_mapping"
        assert claims[mapping.claim_id].attack_mapping.rationale == mapping.reason
    assert before == content_digest([o.model_dump(mode="json") for o in objects])
    print(json.dumps({"fixture": "synthetic A -> B -> C with observed shell command", "nodes": 3,
        "edges": 2, "attack_mappings": len(result.attack_techniques), "grounding": result.grounding_status,
        "production_unchanged": True, "soc_output": result.model_dump(mode="json")}, ensure_ascii=False))


def test_task072_empty_mapping_and_unknown_stage(singleton_context):
    result = ExplanationService(FakeProvider()).explain(singleton_context)
    assert result.status == "available" and result.attack_techniques == []
    assert "insufficient_attack_mapping" in {u.code for u in result.uncertainties}
    assert all(m.attack_mapping is None for m in result.explanation.claims)


def test_task072_cache_catalog_version_contents_mapping_and_prompt(shell_chain_source, monkeypatch):
    from app.ai.attack_catalog import load_catalog, AttackCatalog
    import app.ai.explanation as module
    catalog = load_catalog()
    provider = FakeProvider()
    service = ExplanationService(provider)
    context = context_from(shell_chain_source, attack_catalog=catalog)
    first = service.explain(context)
    assert service.explain(context).explanation == first.explanation and provider.calls == 1
    for field in ("version", "mapping_version"):
        value = catalog.model_dump(mode="json")
        value[field] += "-changed"
        updated = AttackCatalog.model_validate(value)
        revised = context_from(shell_chain_source, attack_catalog=updated)
        assert revised.input_digest != context.input_digest
        assert service.explain(revised).status == "available"
    value = catalog.model_dump(mode="json")
    value["rules"]["unix_shell"]["executables"].remove("/bin/sh")
    revised = context_from(shell_chain_source, attack_catalog=AttackCatalog.model_validate(value))
    assert revised.input_digest != context.input_digest
    assert len(service.explain(revised).attack_techniques) == 1
    assert provider.calls == 4
    monkeypatch.setattr(module, "PROMPT_VERSION", "synthetic-prompt-version")
    assert service.explain(context).explanation.explanation_id != first.explanation.explanation_id
    assert provider.calls == 5
    reordered = catalog.model_dump(mode="json")
    reordered["techniques"].reverse()
    for rule in reordered["rules"].values():
        rule["categories"].reverse()
        rule["executables"].reverse()
    assert context_from(shell_chain_source, attack_catalog=AttackCatalog.model_validate(reordered)) == context


def test_task072_report_refuses_pending_or_rejected(shell_singleton_context):
    from app.ai.report import json_report, markdown_report
    from app.models.enums import GroundingStatus
    explanation = ExplanationService(FakeProvider()).explain(shell_singleton_context).explanation
    for state in (GroundingStatus.PENDING, GroundingStatus.REJECTED):
        with pytest.raises(ValueError, match="validated"):
            markdown_report(explanation.model_copy(update={"grounding_status": state}))
    bad = explanation.claims[0].model_copy(update={"grounding_status": GroundingStatus.PENDING})
    with pytest.raises(ValueError, match="validated"):
        json_report(explanation.model_copy(update={"claims": [bad]}))


def test_task072_api_mapping_rejection_is_http200(explain_api):
    client, app, aid, iid = explain_api
    app.state.explanations = ExplanationService(FakeProvider("mapping_unknown"))
    response = client.post(f"/api/v1/incidents/{iid}/explain", params={"analysis_id": aid})
    assert response.status_code == 200, response.text
    assert response.json()["rejected_mappings"]
    assert response.json()["summary"] and response.json()["assessment"]
    assert "T9999" not in response.json()["report_markdown"]


def test_task072_chain_api_http_provider_and_grounded_mapping(tmp_path):
    import httpx
    from pydantic import SecretStr
    from app.ai.provider import ProviderConfig
    from app.ai.providers.openai_compatible import OpenAICompatibleProvider
    from app.ai.providers.fake import valid_draft
    config, sources = deployment(tmp_path, edge=True)
    app = create_app(tmp_path, configs={"v0": config}, sources=sources)
    records = edge_records()
    records[0]["data"]["command"] = "/bin/sh -c id"
    path = write_input(tmp_path, records)
    aid = app.state.analyses.create(request_for(path), background=False)
    iid = app.state.queries.list(aid, "incidents", page=1, page_size=20, filters={})["items"][0].incident_id
    context = load_context(app.state.queries, aid, iid)
    seen = []
    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        projected = json.loads(body["messages"][1]["content"])["ExplanationContext"]
        assert projected["attack_mapping_options"] and projected["attack_catalog_digest"]
        assert "raw_alert" not in request.content.decode()
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps(valid_draft(context), ensure_ascii=False)}}]})
    provider = OpenAICompatibleProvider(ProviderConfig(base_url="https://provider.invalid/v1", model="synthetic-model",
        api_key=SecretStr("fixture-placeholder")), transport=httpx.MockTransport(handler))
    app.state.explanations = ExplanationService(provider)
    with TestClient(app) as client:
        scope = {"analysis_id": aid}
        before = client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json()
        response = client.post(f"/api/v1/incidents/{iid}/explain", params=scope)
        assert response.status_code == 200, response.text
        result = response.json()
        assert len(result["attack_techniques"]) == 2
        assert len(before["chain"]["nodes"]) == 2 and len(before["chain"]["edges"]) == 1
        assert len(result["attack_progression"]) == 1 and result["grounding_status"] == "validated"
        assert result["provider_metadata"]["provider"] == "openai_compatible"
        assert client.get(f"/api/v1/incidents/{iid}/chain", params=scope).json() == before
        assert "fixture-placeholder" not in response.text
        schema = client.get("/openapi.json").json()["components"]["schemas"]
        assert {"supporting_fact_ids", "evidence_refs", "confidence"} <= schema["GroundedTechnique"]["properties"].keys()
    assert len(seen) == 1


def test_task072_real_singleton_fake_api_smoke(monkeypatch):
    reads = tripwire(monkeypatch)
    q = QueryService(ROOT)
    runs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "data/processed").glob("ana_*/run.json"))]
    runs = [r for r in runs if r.get("status") == "completed" and r.get("config_version") == "v0" and r.get("candidate_contract_version") == "v1.1"
            and {"ait_ads.russellmitchell.wazuh", "ait_ads.russellmitchell.aminer"} <=
                {i.get("source_namespace") for i in r.get("input_files", [])}]
    assert runs, "required real baseline absent"
    run = max(runs, key=lambda r: (r["created_at"], r["analysis_id"]))
    aid = run["analysis_id"]
    assert run["counts"]["chain_edge_count"] == run["counts"]["correlation_edge_count"] == 0
    incident = next(i for i in q.list(aid, "incidents", page=1, page_size=100, filters={})["items"] if len(i.alert_ids) == 1)
    paths = [p for p in (ROOT / "data/processed" / aid).iterdir() if p.is_file()]
    paths += [ROOT / "outputs/analyses" / aid / "manifest.json"]
    before = {str(p): file_digest(p) for p in paths}
    from app.api.routes import router
    api = FastAPI()
    api.state.queries = q
    api.state.explanations = ExplanationService(FakeProvider())
    api.include_router(router)
    with TestClient(api) as client:
        response = client.post(f"/api/v1/incidents/{incident.incident_id}/explain", params={"analysis_id": aid})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["grounding_status"] == "validated" and not result["attack_progression"]
    assert result["summary"] and result["assessment"] and result["risk"] and result["recommended_actions"]
    assert before == {str(p): file_digest(p) for p in paths}
    assert not any("evaluation" in p.lower() or "labels.csv" in p.lower() for p in reads)
    print(json.dumps({"dataset": "AIT-ADS/russellmitchell", "analysis_id": aid, "incident_id": incident.incident_id,
        "type": "singleton", "attack_mapping_count": len(result["attack_techniques"]), "grounding": result["grounding_status"],
        "http_status": response.status_code, "provider": "explicit offline FakeProvider", "nodes": 1, "edges": 0,
        "production_snapshot_unchanged": True, "soc_output": result}, ensure_ascii=False))


# Task 07.3 production integration / export acceptance. Synthetic cases stay
# in tests; the real probe below reads published snapshots without discovery.
def assert_formal_closure(result, context):
    from app.ai.grounding import references, evidence_for
    from app.ai.prompts import render_fact, ACTION_TEMPLATES, RECOMMENDATION_REASON
    from app.models.ai import GroundedProposition
    from app.utils.stable_id import canonical_json, pointer_set
    data = context.data
    subjects = {(kind, oid): value for kind, table in
        (("alert", "alerts"), ("node", "nodes"), ("chain_edge", "edges"), ("correlation_edge", "correlations"))
        for oid, value in data["facts"][table].items()}
    assert result.grounding_status == "validated"
    assert result.report_json["analysis_id"] == data["analysis_id"]
    assert result.report_json["incident_id"] == data["incident"]["incident_id"]
    assert result.report_json["chain_id"] == data["chain_id"]
    for claim in result.explanation.claims:
        assert claim.grounding_status.value == "validated"
        assert claim.claim_id == id_for("AIClaim", claim)
        assert set(claim.alert_ids) <= data["facts"]["alerts"].keys()
        assert set(claim.node_ids) <= data["facts"]["nodes"].keys()
        assert set(claim.edge_ids) <= data["facts"]["edges"].keys()
        if claim.kind.value == "fact":
            ps = [GroundedProposition.model_validate(v.model_dump(), context={"subjects": subjects})
                  for v in claim.propositions]
            refs = references(ps, data["facts"])
            assert claim.alert_ids == refs["alert_refs"]
            assert claim.node_ids == refs["node_refs"] and claim.edge_ids == refs["edge_refs"]
            assert claim.text == render_fact(ps, data["facts"])
        elif claim.kind.value == "recommendation":
            assert claim.text in {v + " " + RECOMMENDATION_REASON for v in ACTION_TEMPLATES.values()}
        else:
            assert claim.kind.value == "attack_mapping"
            mapping = next(m for m in result.attack_techniques if m.claim_id == claim.claim_id)
            assert mapping.mapping_status == "validated" and mapping.reason == claim.text
    claims = {c.claim_id: c for c in result.explanation.claims}
    for item in [*result.summary, *result.key_findings, *result.assessment, *result.attack_progression]:
        assert claims[item.claim_id].text == item.statement
        refs = {key: getattr(item, key) for key in ("object_refs", "node_refs", "edge_refs", "alert_refs")}
        assert pointer_set([p.model_dump() for p in item.evidence_refs]) == evidence_for(refs, data)
    for entity in result.key_entities:
        assert entity.value == data["facts"]["entities"][entity.entity_id]["value"]
        assert entity.alert_refs and set(entity.alert_refs) <= data["facts"]["alerts"].keys()
        assert pointer_set([p.model_dump() for p in entity.evidence_refs]) == data["object_evidence"][entity.entity_id]
    report = json.dumps(result.report_json, ensure_ascii=False)
    assert not {"rejected_claims", "rejected_mappings", "generation_digest", "validation_errors", "raw_generation"} & result.report_json.keys()
    assert "raw_alert" not in report and "labels.csv" not in report
    assert result.explanation.explanation_id == id_for("AIExplanation", result.explanation)


def test_task073_partial_claim_rejection_and_report_exports(shell_chain_context, tmp_path):
    from app.ai.providers.fake import valid_draft
    bad = json.loads(json.dumps(valid_draft(shell_chain_context)["key_findings"][0]))
    bad["statement"] = "UNSUPPORTED_EXFILTRATION 已经外传所有数据。"
    def mutate(d):
        d["key_findings"].append(bad)
        d["attack_techniques"].append({**d["attack_techniques"][0], "technique_id": "T9999"})
    result = ExplanationService(FakeProvider(transform=mutate)).explain(shell_chain_context)
    assert result.status == "available" and result.generation_status == "partially_rejected"
    assert len(result.rejected_claims) == 1 and len(result.rejected_mappings) == 1
    assert len(result.attack_techniques) == 2 and len(result.attack_progression) == 2
    assert "unsupported_fact_text" in result.rejected_claims[0].validation_errors
    assert_formal_closure(result, shell_chain_context)
    for filename, content in (("report.json", json.dumps(result.report_json, ensure_ascii=False)),
                              ("report.md", result.report_markdown)):
        path = tmp_path / filename
        path.write_text(content, encoding="utf-8")
        exported = path.read_text(encoding="utf-8")
        assert "UNSUPPORTED_EXFILTRATION" not in exported and "T9999" not in exported
        assert "rejected_claims" not in exported and "rejected_mappings" not in exported
        assert result.analysis_id in exported and result.incident_id in exported


def test_task073_all_claims_rejected_fallback_and_recovery(singleton_context):
    def mutate(d):
        for item in [*d["summary"], *d["key_findings"]]:
            item["statement"] = "UNSUPPORTED_ALL 已经提权并建立 C2。"
        d["recommended_actions"] = []
    provider = FakeProvider(transform=mutate)
    service = ExplanationService(provider)
    result = service.explain(singleton_context)
    assert result.status == "validation_failed" and result.generation_status == "grounding_rejected"
    assert result.result_origin == "deterministic" and result.degraded and result.rejected_claims
    assert not result.attack_techniques and not result.attack_progression
    assert "UNSUPPORTED_ALL" not in result.report_markdown + json.dumps(result.report_json)
    assert_formal_closure(result, singleton_context)
    assert not service._cache
    provider.transform = None
    assert service.explain(singleton_context).generation_status == "succeeded"
    assert provider.calls == 2


@pytest.mark.parametrize("mode", [None, "timeout", "invalid_json", "missing_field", "empty"])
def test_task073_failure_reports_are_grounded(singleton_context, mode):
    result = ExplanationService(FakeProvider(mode) if mode else None).explain(singleton_context)
    assert result.degraded and result.result_origin == "deterministic"
    assert result.explanation.provider == "deterministic" and not result.attack_techniques
    assert result.summary and result.risk and result.recommended_actions
    assert "没有得到证据支持的多阶段" in result.report_markdown
    assert_formal_closure(result, singleton_context)


@pytest.mark.parametrize("scenario,code", [("timeout", "provider_timeout"), ("http", "provider_http_error"),
    ("connection", "provider_transport_error"), ("envelope", "provider_invalid_response"),
    ("json", "provider_invalid_draft"), ("schema", "provider_invalid_draft")])
def test_task073_http_failure_api_reports_and_discovery_immutability(explain_api, scenario, code):
    import httpx
    from app.ai.providers.openai_compatible import OpenAICompatibleProvider
    from test_llm_provider import configured
    from app.services.storage import MODELS
    client, app, aid, iid = explain_api
    def handler(request):
        if scenario == "timeout":
            raise httpx.ReadTimeout("sensitive provider text", request=request)
        if scenario == "connection":
            raise httpx.ConnectError("sensitive provider text", request=request)
        if scenario == "http":
            return httpx.Response(503, text="sensitive provider text")
        if scenario == "envelope":
            return httpx.Response(200, text="sensitive provider text")
        return httpx.Response(200, json={"choices": [{"message": {"content": "{broken" if scenario == "json" else "{}"}}]})
    app.state.explanations = ExplanationService(OpenAICompatibleProvider(configured(), transport=httpx.MockTransport(handler)))
    store = app.state.queries.store(aid)
    paths = [store.domain / (kind + ".parquet") for kind in MODELS]
    paths += [store.domain / "analysis.json", store.domain / "run.json", store.details / "manifest.json"]
    before = {str(p): file_digest(p) for p in paths}
    scope = {"analysis_id": aid}
    response = client.post(f"/api/v1/incidents/{iid}/explain", params=scope)
    assert response.status_code == 409 and response.json()["detail"] == code
    from app.ai.explanation import GroundedExplanation
    result = GroundedExplanation.model_validate_json(response.text)
    assert_formal_closure(result, load_context(app.state.queries, aid, iid))
    assert result.degraded and result.result_origin == "deterministic"
    assert "sensitive provider text" not in response.text and "fixture-placeholder" not in response.text
    assert client.get(f"/api/v1/analyses/{aid}").json()["status"] == "completed"
    assert client.get(f"/api/v1/incidents/{iid}", params=scope).status_code == 200
    assert client.get(f"/api/v1/incidents/{iid}/chain", params=scope).status_code == 200
    assert before == {str(p): file_digest(p) for p in paths}


def test_task073_cache_provider_configuration_and_schema(singleton_context, monkeypatch):
    import httpx
    from pydantic import SecretStr
    from app.ai.providers.fake import valid_draft
    from app.ai.providers.openai_compatible import OpenAICompatibleProvider
    from test_llm_provider import configured
    from app.ai.explanation import ExplanationDraft
    sent = []
    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(valid_draft(singleton_context))}}]})
    provider = OpenAICompatibleProvider(configured(), transport=httpx.MockTransport(handler))
    service = ExplanationService(provider)
    first = service.explain(singleton_context)
    assert service.explain(singleton_context) == first and len(sent) == 1
    for changes in ({"base_url": "https://second-provider.invalid/v1"}, {"timeout_seconds": 20.0},
                    {"api_key": SecretStr("second-fixture-placeholder")}):
        provider.config = provider.config.model_copy(update=changes)
        assert service.explain(singleton_context).status == "available"
    assert len(sent) == 4
    original = ExplanationDraft.model_json_schema
    monkeypatch.setattr(ExplanationDraft, "model_json_schema", classmethod(lambda cls: {**original(), "description": "new-schema"}))
    service.explain(singleton_context)
    assert len(sent) == 5
    assert all("fixture-placeholder" not in str(key) for key in service._cache)


def test_task073_analysis_incident_cache_isolation_and_foreign_evidence(tmp_path):
    from app.ai.explanation import GroundedExplanation
    config, sources = deployment(tmp_path)
    app = create_app(tmp_path, configs={"v0": config}, sources=sources)
    path = write_input(tmp_path, [synthetic_record(), synthetic_record(id="synthetic-other-id",
        timestamp="2026-01-01T00:00:00Z")])
    aid = app.state.analyses.create(request_for(path), background=False)
    bid = app.state.analyses.create(request_for(path), background=False)
    # Task 05 execution identities differ even with identical alert/Incident IDs.
    assert aid != bid
    incidents = app.state.queries.list(aid, "incidents", page=1, page_size=20, filters={})["items"]
    assert len(incidents) == 2
    provider = FakeProvider()
    app.state.explanations = ExplanationService(provider)
    with TestClient(app) as client:
        for identity in (aid, bid):
            for incident in incidents:
                scope = {"analysis_id": identity}
                response = client.post(f"/api/v1/incidents/{incident.incident_id}/explain", params=scope)
                assert response.status_code == 200, response.text
                result = GroundedExplanation.model_validate_json(response.text)
                assert_formal_closure(result, load_context(app.state.queries, identity, incident.incident_id))
        assert provider.calls == 4 and len(app.state.explanations._cache) == 4
        # A valid observation from a different Incident/Analysis must not pass.
        foreign = load_context(app.state.queries, bid, incidents[-1].incident_id)
        provider.transform = lambda d: d["key_findings"].extend(valid_draft(foreign)["summary"])
        app.state.explanations = ExplanationService(provider)
        response = client.post(f"/api/v1/incidents/{incidents[0].incident_id}/explain", params={"analysis_id": aid})
        result = GroundedExplanation.model_validate_json(response.text)
        assert result.rejected_claims and "unsupported_proposition" in result.validation_errors
        assert_formal_closure(result, load_context(app.state.queries, aid, incidents[0].incident_id))
        # Cache hit cannot bypass snapshot lookup or file integrity verification.
        provider.transform = None
        app.state.explanations = ExplanationService(provider)
        client.post(f"/api/v1/incidents/{incidents[0].incident_id}/explain", params={"analysis_id": aid})
        with (app.state.queries.store(aid).domain / "alerts.parquet").open("ab") as f:
            f.write(b"corrupt")
        response = client.post(f"/api/v1/incidents/{incidents[0].incident_id}/explain", params={"analysis_id": aid})
        assert response.status_code == 409 and response.json()["detail"] == "snapshot_integrity_error"


def test_task073_multistep_all_objects_and_nonexistent_topology(shell_chain_context, shell_chain_source):
    objects = [shell_chain_source[1], shell_chain_source[2], *shell_chain_source[2].nodes, *shell_chain_source[2].edges,
        *shell_chain_source[3].alerts.values(), *shell_chain_source[3].entities.values(), *shell_chain_source[4].edges]
    before = content_digest([o.model_dump(mode="json") for o in objects])
    def mutate(d):
        fake = json.loads(json.dumps(d["key_findings"][0]))
        fake.update(statement="UNOBSERVED_D", node_refs=["nod_" + "f" * 64], edge_refs=["che_" + "f" * 64])
        d["key_findings"].append(fake)
    result = ExplanationService(FakeProvider(transform=mutate)).explain(shell_chain_context)
    assert result.rejected_claims and len(result.attack_progression) == 2
    assert "UNOBSERVED_D" not in result.report_markdown
    assert_formal_closure(result, shell_chain_context)
    assert before == content_digest([o.model_dump(mode="json") for o in objects])


def test_task073_unconfigured_http_provider_is_explicit_fallback(singleton_context):
    import httpx
    from app.ai.provider import ProviderConfig
    from app.ai.providers.openai_compatible import OpenAICompatibleProvider
    provider = OpenAICompatibleProvider(ProviderConfig(), transport=httpx.MockTransport(
        lambda _: pytest.fail("missing configuration must not send HTTP")))
    result = ExplanationService(provider).explain(singleton_context)
    assert result.status == "unavailable" and result.generation_status == "provider_unavailable"
    assert result.provider_metadata.model == "unconfigured" and result.result_origin == "deterministic"
    assert_formal_closure(result, singleton_context)


def test_task073_incident_status_and_content_invalidate_cache(chain_source):
    from app.models.enums import IncidentStatus
    aid, inc, chain, index, correlations, _ = chain_source
    provider = FakeProvider()
    service = ExplanationService(provider)
    original = context_from(chain_source)
    service.explain(original)
    updated = inc.model_copy(update={"status": IncidentStatus.INVESTIGATING})
    revised = build_context(aid, updated, chain, [index.alerts[a] for a in inc.alert_ids],
        [index.entities[e] for e in inc.entity_ids], [c for c in correlations.edges if c.edge_id in inc.correlation_edge_ids])
    assert revised.input_digest != original.input_digest
    assert service.explain(revised).status == "available" and provider.calls == 2


def test_task073_real_three_source_snapshot_api_reports(monkeypatch, tmp_path):
    import duckdb
    from app.api.routes import router
    from app.ai.explanation import GroundedExplanation
    from app.services.storage import MODELS
    reads = tripwire(monkeypatch)
    runs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "data/processed").glob("ana_*/run.json"))]
    runs = [r for r in runs if r.get("status") == "completed" and r.get("candidate_contract_version") == "v1.1"
        and {"ait_ads.russellmitchell.wazuh", "ait_ads.russellmitchell.aminer"} <=
        {i.get("source_namespace") for i in r.get("input_files", [])}]
    assert runs, "required real production Analysis Snapshot missing"
    run = max(runs, key=lambda r: (r["created_at"], r["analysis_id"]))
    aid = run["analysis_id"]
    q = QueryService(ROOT)
    store = q.ready(aid)
    paths = [store.domain / (kind + ".parquet") for kind in MODELS]
    paths += [store.domain / "analysis.json", store.domain / "run.json",
              store.details / "manifest.json", store.details / "diagnostics.jsonl", store.details / "frequency_snapshot.json"]
    before = {str(p): file_digest(p) for p in paths}
    selected = []
    # Query production objects, selecting existing singleton members by source.
    with duckdb.connect(":memory:") as db:
        for source in ("aminer", "wazuh", "suricata"):
            row = db.execute("SELECT i.object_id FROM read_parquet(?) i JOIN read_parquet(?) a "
                "ON json_extract_string(i.payload, '$.alert_ids[0]') = a.object_id "
                "WHERE json_array_length(i.payload, '$.alert_ids') = 1 AND "
                "json_extract_string(a.payload, '$.source_type') = ? ORDER BY i.object_id LIMIT 1",
                [q.table(store, "incidents"), q.table(store, "alerts"), source]).fetchone()
            assert row, "real singleton absent for " + source
            selected.append((source, row[0]))
    api = FastAPI()
    api.state.queries = q
    api.state.explanations = ExplanationService(FakeProvider())
    api.include_router(router)
    measurements = []
    with TestClient(api) as client:
        assert client.get(f"/api/v1/analyses/{aid}").status_code == 200
        for source, iid in selected:
            scope = {"analysis_id": aid}
            incident = client.get(f"/api/v1/incidents/{iid}", params=scope)
            assert incident.status_code == 200 and len(incident.json()["incident"]["alert_ids"]) == 1
            response = client.post(f"/api/v1/incidents/{iid}/explain", params=scope)
            assert response.status_code == 200, response.text
            result = GroundedExplanation.model_validate_json(response.text)
            context = load_context(q, aid, iid)
            assert_formal_closure(result, context)
            assert result.status == "available" and result.grounding_status == "validated"
            assert not result.attack_progression and not result.rejected_claims and not result.rejected_mappings
            assert not result.degraded and result.provider_metadata.provider == "fake"
            for pointer in context.data["evidence_refs"]:
                assert client.get("/api/v1/alerts/" + pointer["alert_id"], params=scope).status_code == 200
            (tmp_path / (source + ".json")).write_text(json.dumps(result.report_json, ensure_ascii=False, indent=2), encoding="utf-8")
            (tmp_path / (source + ".md")).write_text(result.report_markdown, encoding="utf-8")
            measurements.append({"source_type": source, "incident_id": iid, "type": "singleton",
                "verified_claims": len(result.explanation.claims), "attack_mappings": len(result.attack_techniques),
                "rejected_claims": len(result.rejected_claims), "rejected_mappings": len(result.rejected_mappings),
                "http_status": response.status_code, "provider": "explicit offline FakeProvider",
                "exports": [source + ".json", source + ".md"]})
    assert before == {str(p): file_digest(p) for p in paths}
    assert not any("evaluation" in p.lower() or "labels.csv" in p.lower() for p in reads)
    print(json.dumps({"task": "07.3", "dataset": "AIT-ADS/russellmitchell", "analysis_id": aid,
        "incidents": measurements, "unsupported_formal_claims": 0, "broken_evidence_references": 0,
        "cross_analysis_references": 0, "snapshot_hashes_unchanged": True}, ensure_ascii=False))

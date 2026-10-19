"""HTTP protocol tested with HTTPX MockTransport only; zero paid requests."""

import json
from pathlib import Path
import shutil
import socket
import subprocess

import httpx
from pydantic import SecretStr
import pytest

from app.ai.provider import ProviderConfig, ProviderError, load_provider_config
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.ai.providers.fake import valid_draft
from app.ai.prompts import SYSTEM_PROMPT
from test_ai_explanation import algorithm, offline, singleton_context


def configured(**changes):
    # Test-only placeholder, never a real credential.
    return ProviderConfig(base_url="https://provider.invalid/v1", model="test-model", api_key=SecretStr("fixture-placeholder"), **changes)


def test_environment_and_secret_exclusion(tmp_path):
    path = tmp_path / "llm.yaml"
    path.write_text("provider: openai_compatible\nbase_url: null\nmodel: null\ntimeout_seconds: 10.0\n", encoding="utf-8")
    cfg = load_provider_config(path, {"TRACEBACK_LLM_BASE_URL": "https://provider.invalid/v1/",
                                    "TRACEBACK_LLM_MODEL": "test-model", "TRACEBACK_LLM_API_KEY": "fixture-placeholder"})
    assert cfg.configured and cfg.base_url == "https://provider.invalid/v1"
    assert "fixture-placeholder" not in repr(cfg) + cfg.model_dump_json()
    assert not load_provider_config(path, {}).configured
    assert "api_key" not in cfg.model_dump()
    path.write_text("api_key: fixture-placeholder\n", encoding="utf-8")
    assert load_provider_config(path, {}).api_key.get_secret_value() == "fixture-placeholder"
    path.write_text("provider: [unterminated", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_provider_config"):
        load_provider_config(path, {})


def test_inline_key_and_environment_precedence(tmp_path):
    path = tmp_path / "llm.yaml"
    settings = "base_url: https://provider.invalid/v1\nmodel: test-model\n"
    path.write_text(settings + 'api_key: " inline-fixture-placeholder "\n', encoding="utf-8-sig")
    # A filled llm.yaml takes precedence over the legacy sibling file.
    (tmp_path / "llm.local.yaml").write_text("api_key: legacy-fixture-placeholder\n", encoding="utf-8")
    cfg = load_provider_config(path, {})
    assert cfg.configured and cfg.api_key.get_secret_value() == "inline-fixture-placeholder"
    assert "api_key" not in cfg.model_dump()
    assert "inline-fixture-placeholder" not in repr(cfg) + cfg.model_dump_json()
    override = load_provider_config(path, {"TRACEBACK_LLM_API_KEY": "env-fixture-placeholder"})
    assert override.api_key.get_secret_value() == "env-fixture-placeholder"
    (tmp_path / "llm.local.yaml").unlink()
    for value in ('""', '"   "', "null"):
        path.write_text(settings + "api_key: " + value + "\n", encoding="utf-8")
        assert not load_provider_config(path, {}).configured


@pytest.mark.parametrize("content", [
    "api_key: [inline-fixture-placeholder", "api_key: [inline-fixture-placeholder]\n",
    "api_key: 123\n", "api_key: true\n", "inline-fixture-placeholder\n",
    "api_key: inline-fixture-placeholder\ntimeout_seconds: invalid\n",
    "api_key: inline-fixture-placeholder\nunknown_option: true\n",
])
def test_invalid_inline_key_config_has_safe_error(tmp_path, content):
    path = tmp_path / "llm.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError) as error:
        load_provider_config(path, {})
    assert str(error.value) == "invalid_provider_config"
    assert error.value.__suppress_context__ or error.value.__context__ is None


def test_local_key_and_environment_precedence(tmp_path):
    path = tmp_path / "llm.yaml"
    path.write_text("base_url: https://provider.invalid/v1\nmodel: test-model\n", encoding="utf-8")
    local = tmp_path / "llm.local.yaml"
    local.write_text('api_key: " local-fixture-placeholder "\n', encoding="utf-8-sig")
    cfg = load_provider_config(path, {})
    assert cfg.configured and cfg.api_key.get_secret_value() == "local-fixture-placeholder"
    assert "api_key" not in cfg.model_dump()
    assert "local-fixture-placeholder" not in repr(cfg) + cfg.model_dump_json()
    override = load_provider_config(path, {"TRACEBACK_LLM_API_KEY": "env-fixture-placeholder"})
    assert override.api_key.get_secret_value() == "env-fixture-placeholder"
    assert "env-fixture-placeholder" not in repr(override) + override.model_dump_json()
    for content in ('api_key: ""\n', 'api_key: "   "\n', "api_key: null\n", "{}\n"):
        local.write_text(content, encoding="utf-8")
        assert not load_provider_config(path, {}).configured
    local.unlink()
    assert not load_provider_config(path, {}).configured


@pytest.mark.parametrize("content", [
    "api_key: [local-fixture-placeholder", "api_key: [local-fixture-placeholder]\n",
    "api_key: 123\n", "api_key: true\n", "local-fixture-placeholder\n",
    "api_key: local-fixture-placeholder\nmodel: unwanted-model\n",
])
def test_invalid_local_key_has_safe_error(tmp_path, content):
    path = tmp_path / "llm.yaml"
    path.write_text("{}\n", encoding="utf-8")
    (tmp_path / "llm.local.yaml").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError) as error:
        load_provider_config(path, {})
    assert str(error.value) == "invalid_provider_local_config"
    assert error.value.__suppress_context__ or error.value.__context__ is None


@pytest.mark.parametrize("inline", [True, False])
def test_file_key_used_only_for_http_authorization(tmp_path, singleton_context, inline):
    path = tmp_path / "llm.yaml"
    path.write_text("base_url: https://provider.invalid/v1\nmodel: test-model\n", encoding="utf-8")
    if inline:
        with path.open("a", encoding="utf-8") as stream:
            stream.write('api_key: "local-fixture-placeholder"\n')
    else:
        (tmp_path / "llm.local.yaml").write_text('api_key: "local-fixture-placeholder"\n', encoding="utf-8")
    seen = []
    def handler(request):
        seen.append(request)
        assert request.headers["authorization"] == "Bearer local-fixture-placeholder"
        assert "local-fixture-placeholder" not in request.content.decode()
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps(valid_draft(singleton_context), ensure_ascii=False)}}]})
    provider = OpenAICompatibleProvider(load_provider_config(path, {}), transport=httpx.MockTransport(handler))
    from app.ai.explanation import ExplanationService
    result = ExplanationService(provider).explain(singleton_context)
    assert result.status == "available" and len(seen) == 1
    assert "local-fixture-placeholder" not in result.model_dump_json()


def test_git_ignores_local_key_but_keeps_template(tmp_path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required to verify ignore rules")
    root = Path(__file__).resolve().parents[2]
    (tmp_path / ".gitignore").write_bytes((root / ".gitignore").read_bytes())
    (tmp_path / "configs").mkdir()
    for name in ("llm.yaml", "llm.example.yaml", "llm.local.yaml", "llm.local.example.yaml"):
        (tmp_path / "configs" / name).write_text('api_key: ""\n', encoding="utf-8")
    subprocess.run([git, "init", "--quiet", str(tmp_path)], check=True, capture_output=True)
    for name, expected in (("llm.yaml", 0), ("llm.example.yaml", 1),
                           ("llm.local.yaml", 0), ("llm.local.example.yaml", 1)):
        result = subprocess.run([git, "-C", str(tmp_path), "check-ignore", "--no-index", "configs/" + name],
                                capture_output=True, text=True)
        assert result.returncode == expected
    status = subprocess.run([git, "-C", str(tmp_path), "status", "--short", "--untracked-files=all"],
                            check=True, capture_output=True, text=True).stdout
    assert "configs/llm.local.yaml" not in status
    assert "configs/llm.yaml" not in status
    assert "configs/llm.example.yaml" in status
    assert "configs/llm.local.example.yaml" in status


@pytest.mark.parametrize("changes", [{"base_url": "file:///anything"}, {"base_url": "https://user:secret@provider.invalid"},
    {"base_url": "https://provider.invalid/?token=secret"}, {"timeout_seconds": 0.0},
    {"max_retries": 3}, {"unrecognized": True}, {"timeout_seconds": float("inf")}])
def test_invalid_config_rejected(changes):
    with pytest.raises(ValueError):
        ProviderConfig.model_validate(changes)


def test_http_success_request_whitelist_and_prompt_contract(singleton_context):
    seen = []
    def handler(request):
        seen.append(json.loads(request.content))
        assert str(request.url) == "https://provider.invalid/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer fixture-placeholder"
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(valid_draft(singleton_context), ensure_ascii=False)}}]})
    provider = OpenAICompatibleProvider(configured(), transport=httpx.MockTransport(handler))
    text = provider.explain(singleton_context)
    assert json.loads(text)["incident_id"] == singleton_context.data["incident"]["incident_id"]
    assert len(seen) == 1 and seen[0]["response_format"] == {"type": "json_object"}
    body = json.loads(seen[0]["messages"][1]["content"])
    assert body["ExplanationContext"] == singleton_context.data
    assert body["output_schema"]["additionalProperties"] is False
    assert "raw_alert" not in json.dumps(body) and "fixture-placeholder" not in json.dumps(body)
    for text in ("事件解释器", "不是事件发现器", "禁止改变边方向", "Incident 成员", "propositions", "不确定性", "建议尚未执行"):
        assert text in SYSTEM_PROMPT


@pytest.mark.parametrize("scenario,code", [("timeout", "provider_timeout"), ("429", "provider_rate_limited"),
    ("500", "provider_http_error"), ("401", "provider_http_error"), ("302", "provider_http_error"),
    ("network", "provider_transport_error"), ("invalid_json", "provider_invalid_response"),
    ("missing", "provider_invalid_response"), ("empty", "provider_empty_response"), ("truncated", "provider_incomplete_response")])
def test_http_error_codes_retries_and_no_secret_leak(singleton_context, scenario, code):
    count = []
    def handler(request):
        count.append(1)
        if scenario == "timeout":
            raise httpx.ReadTimeout("fixture-placeholder", request=request)
        if scenario == "network":
            raise httpx.ConnectError("fixture-placeholder", request=request)
        if scenario.isdigit():
            return httpx.Response(int(scenario), text="fixture-placeholder")
        if scenario == "invalid_json":
            return httpx.Response(200, text="not JSON: fixture-placeholder")
        if scenario == "missing":
            return httpx.Response(200, json={"choices": []})
        return httpx.Response(200, json={"choices": [{"finish_reason": "length" if scenario == "truncated" else "stop",
                                                    "message": {"content": "x" if scenario == "truncated" else ""}}]})
    provider = OpenAICompatibleProvider(configured(max_retries=2), transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderError) as error:
        provider.explain(singleton_context)
    assert error.value.code == code and "fixture-placeholder" not in str(error.value)
    assert len(count) == (3 if scenario in {"timeout", "network", "429", "500"} else 1)


def test_retry_recovers_and_size_limits(singleton_context):
    seen = []
    def handler(request):
        seen.append(1)
        return httpx.Response(429) if len(seen) == 1 else httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
    assert OpenAICompatibleProvider(configured(), transport=httpx.MockTransport(handler)).explain(singleton_context) == "{}"
    assert len(seen) == 2
    large = httpx.MockTransport(lambda _: httpx.Response(200, text="x" * 2000))
    with pytest.raises(ProviderError, match="provider_response_too_large"):
        OpenAICompatibleProvider(configured(max_response_bytes=1024), transport=large).explain(singleton_context)
    with pytest.raises(ProviderError, match="context_size_exceeded"):
        OpenAICompatibleProvider(configured(max_context_bytes=1024), transport=large).explain(singleton_context)


def test_unconfigured_provider_never_sends(singleton_context):
    transport = httpx.MockTransport(lambda _: pytest.fail("unconfigured provider must not send HTTP"))
    with pytest.raises(ProviderError, match="provider_not_configured"):
        OpenAICompatibleProvider(ProviderConfig(), transport=transport).explain(singleton_context)

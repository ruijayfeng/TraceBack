"""Bounded HTTPX chat-completions transport, without a vendor SDK."""

import httpx

from app.ai.provider import LLMProvider, ProviderError
from app.ai.prompts import prompt_messages


class OpenAICompatibleProvider(LLMProvider):
    name = "openai_compatible"

    def __init__(self, config, *, transport=None):
        self.config, self.model, self.transport = config, config.model, transport

    @property
    def cache_identity(self):
        from hashlib import sha256
        from app.utils.stable_id import content_digest
        # Credential identity partitions tenants without retaining the secret.
        credential = self.config.api_key.get_secret_value() if self.config.api_key else ""
        return content_digest({"config": self.config.model_dump(mode="json"),
            "credential_digest": sha256(credential.encode()).hexdigest(),
            "model": self.model, "provider": self.name, "transport": id(self.transport)})

    def explain(self, context):
        from app.ai.explanation import ExplanationDraft
        if not self.config.configured:
            raise ProviderError("provider_not_configured")
        payload = context.model_payload if hasattr(context, 'model_payload') else context.payload
        if len(payload.encode("utf-8")) > self.config.max_context_bytes:
            raise ProviderError("context_size_exceeded")
        schema = context.response_schema if hasattr(context, 'response_schema') else ExplanationDraft.model_json_schema()
        messages = context.messages(schema) if hasattr(context, 'messages') else prompt_messages(context, schema)
        body = {"model": self.model, "messages": messages,
                "response_format": {"type": "json_object"}}
        # No redirect can forward credentials to another origin; no ambient proxy.
        with httpx.Client(timeout=self.config.timeout_seconds, transport=self.transport,
                          follow_redirects=False, trust_env=False) as client:
            for attempt in range(self.config.max_retries + 1):
                try:
                    with client.stream("POST", self.config.base_url + "/chat/completions", json=body,
                                       headers={"Authorization": "Bearer " + self.config.api_key.get_secret_value()}) as response:
                        if response.status_code == 429 or response.status_code >= 500:
                            if attempt < self.config.max_retries:
                                continue
                            raise ProviderError("provider_rate_limited" if response.status_code == 429 else "provider_http_error")
                        if response.status_code != 200:
                            raise ProviderError("provider_http_error")
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            size += len(chunk)
                            if size > self.config.max_response_bytes:
                                raise ProviderError("provider_response_too_large")
                            chunks.append(chunk)
                    import json
                    try:
                        envelope = json.loads(b"".join(chunks))
                        choice = envelope["choices"][0]
                        text = choice["message"]["content"]
                        if choice.get("finish_reason") not in {None, "stop"}:
                            raise ProviderError("provider_incomplete_response")
                        if not isinstance(text, str) or not text.strip():
                            raise ProviderError("provider_empty_response")
                        return text
                    except (ValueError, KeyError, IndexError, TypeError):
                        raise ProviderError("provider_invalid_response") from None
                except httpx.TimeoutException:
                    if attempt == self.config.max_retries:
                        raise ProviderError("provider_timeout") from None
                except httpx.HTTPError:
                    if attempt == self.config.max_retries:
                        raise ProviderError("provider_transport_error") from None
        raise ProviderError("provider_transport_error")

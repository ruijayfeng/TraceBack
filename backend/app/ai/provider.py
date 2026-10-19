"""Provider protocol and secret-free deployment configuration."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Annotated, Literal
import os

from pydantic import Field, SecretStr, field_validator
import yaml

from app.models.base import StrictModel, Text


class ProviderError(Exception):
    """Only a fixed code crosses the boundary; never provider response text."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class ProviderConfig(StrictModel):
    provider: Literal["openai_compatible"] = "openai_compatible"
    base_url: Text | None = None
    model: Text | None = None
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    timeout_seconds: Annotated[float, Field(gt=0, le=120, allow_inf_nan=False)] = 30.0
    max_retries: Annotated[int, Field(ge=0, le=2)] = 1
    max_response_bytes: Annotated[int, Field(ge=1024, le=2097152)] = 524288
    max_context_bytes: Annotated[int, Field(ge=1024, le=2097152)] = 524288

    @field_validator("base_url")
    @classmethod
    def checked_url(cls, value):
        if value is None:
            return value
        from urllib.parse import urlsplit
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("invalid_provider_url")
        return value.rstrip("/")

    @property
    def configured(self):
        return bool(self.base_url and self.model and self.api_key and self.api_key.get_secret_value().strip())


def _secret_from_value(key, error_code):
    if key is not None and not isinstance(key, str):
        raise ValueError(error_code)
    return SecretStr(key.strip()) if key and key.strip() else None


def _load_local_api_key(path):
    """Read the ignored sibling file without exposing its contents in errors."""
    try:
        if not path.is_file():
            return None
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (yaml.YAMLError, UnicodeError, OSError):
        raise ValueError("invalid_provider_local_config") from None
    if not isinstance(data, dict) or set(data) - {"api_key"}:
        raise ValueError("invalid_provider_local_config")
    return _secret_from_value(data.get("api_key"), "invalid_provider_local_config")


def load_provider_config(path=None, environ=None):
    """Load ignored local settings; environment values take precedence."""
    path = Path(path or Path(__file__).resolve().parents[3] / "configs/llm.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) if path.is_file() else {}
    except (yaml.YAMLError, UnicodeError, OSError):
        raise ValueError("invalid_provider_config") from None
    if not isinstance(data, dict):
        raise ValueError("invalid_provider_config")
    local_key = _secret_from_value(data.pop("api_key", None), "invalid_provider_config")
    if local_key is None:
        local_key = _load_local_api_key(path.with_name("llm.local.yaml"))
    if local_key is not None:
        data["api_key"] = local_key
    env = os.environ if environ is None else environ
    for field, variable in (("base_url", "TRACEBACK_LLM_BASE_URL"), ("model", "TRACEBACK_LLM_MODEL"),
                            ("api_key", "TRACEBACK_LLM_API_KEY")):
        if env.get(variable):
            data[field] = SecretStr(env[variable]) if field == "api_key" else env[variable]
    try:
        if env.get("TRACEBACK_LLM_TIMEOUT_SECONDS"):
            data["timeout_seconds"] = float(env["TRACEBACK_LLM_TIMEOUT_SECONDS"])
        return ProviderConfig.model_validate(data)
    except ValueError:
        raise ValueError("invalid_provider_config") from None


class LLMProvider(ABC):
    name: str
    model: str

    @property
    def cache_identity(self):
        """Instance-local default; configurable providers supply a content key."""
        if not hasattr(self, "_cache_namespace"):
            self._cache_namespace = object()
        return (type(self).__module__, type(self).__qualname__, self._cache_namespace, self.name, self.model)

    @abstractmethod
    def explain(self, context) -> str:
        """Return JSON draft text. The service, never the provider, approves it."""

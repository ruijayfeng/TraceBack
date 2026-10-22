"""Opt-in, deployment-owned identity authority contracts; no source-name rules."""
from typing import Literal
from pydantic import Field, field_validator, model_validator
from app.models.base import StrictModel, Text, Pointer


class HostAuthority(StrictModel):
    authority_domain: Text
    deployment_scope: Text
    network_scope: Text
    max_alias_age_seconds: int = Field(gt=0, le=86400)
    scope_pointers: tuple[Pointer, ...] = ('/deployment_id', '/network_namespace')

    @field_validator('scope_pointers', mode='before')
    @classmethod
    def sequence(cls, v):
        if not isinstance(v,(list,tuple)):
            raise ValueError('identity_contract_requires_sequence')
        return tuple(sorted(set(v)))


class AuthSessionAuthority(StrictModel):
    authority_domain: Text
    deployment_scope: Text
    session_type: Text
    token_pointer: Pointer
    equivalent_token_pointers: tuple[Pointer, ...] = ()
    start_operations: tuple[Text, ...] = ()
    close_operations: tuple[Text, ...] = ()
    lifecycle_semantics: str
    epoch_pointers: tuple[Pointer, ...] = ('/boot_id', '/session_epoch')
    realm_pointers: tuple[Pointer, ...] = ('/realm', '/account_domain', '/user_domain')

    @field_validator('lifecycle_semantics')
    @classmethod
    def semantics(cls, v):
        if v != 'host_token_until_close':
            raise ValueError('unsupported_session_lifecycle_semantics')
        return v

    @field_validator('token_pointer')
    @classmethod
    def token_semantics(cls, v):
        if v.rsplit('/', 1)[-1] not in {'logon_id', 'auth_session_id'}:
            raise ValueError('auth_projection_requires_authentication_token')
        return v

    @field_validator('equivalent_token_pointers', 'start_operations', 'close_operations', 'epoch_pointers', 'realm_pointers', mode='before')
    @classmethod
    def sequence(cls, v):
        if not isinstance(v,(list,tuple)):
            raise ValueError('identity_contract_requires_sequence')
        return tuple(sorted(set(v)))

    @model_validator(mode='after')
    def typed_aliases_and_boundaries(self):
        if set(self.start_operations)&set(self.close_operations):
            raise ValueError('session_start_and_close_operations_overlap')
        if any(p.rsplit('/',1)[-1] not in {'session_id','auth_session_id','logon_id','session'} for p in self.equivalent_token_pointers):
            raise ValueError('connection_or_flow_cannot_alias_auth_session')
        return self


class ContextAuthority(StrictModel):
    """An issuer contract for one native identifier, never all session fields."""
    kind: Literal['request', 'connection']
    authority_domain: Text
    deployment_scope: Text
    network_scope: Text
    token_pointer: Pointer
    max_age_seconds: int = Field(gt=0, le=86400)
    destination_ip_pointer: Pointer | None = None
    scope_pointers: tuple[Pointer, ...] = ('/deployment_id', '/network_namespace')

    @field_validator('scope_pointers', mode='before')
    @classmethod
    def sequence(cls, value):
        if not isinstance(value, (list,tuple)):
            raise ValueError('context_scope_requires_sequence')
        return tuple(sorted(set(value)))

    @model_validator(mode='after')
    def typed_token(self):
        if self.token_pointer != {'request':'/request_id', 'connection':'/connection_id'}[self.kind]:
            raise ValueError('context_authority_requires_typed_native_token')
        return self


class IdentityAuthorities(StrictModel):
    host: HostAuthority | None = None
    auth_session: AuthSessionAuthority | None = None
    contexts: list[ContextAuthority] | None = None

    @model_validator(mode='after')
    def unique_context_issuers(self):
        kinds=[c.kind for c in self.contexts or []]
        if len(kinds)!=len(set(kinds)):
            raise ValueError('context_kind_requires_single_authority')
        return self

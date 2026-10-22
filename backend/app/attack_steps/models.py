"""Local contracts and deterministic identities; no production model changes."""
from dataclasses import dataclass, field
import hashlib
import json

VERSION = 'attack-step-semantic-v1.1'
TAXONOMY = 'attack-step-taxonomy-v1.1'
P1 = 'P1_REQUEST_RESPONSE_TRANSACTION'
VERSIONS = dict(community='community-v1', stages='behavior-stage-v1',
                candidates='stage-candidates-v1', evidence='stage-evidence-v2',
                chains='attack-chain-reconstruction-v1')

class PrototypeError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise PrototypeError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def jcs(value):
    """RFC8785 for the output's string/bool/null/safe-integer domain.

    Output Schema has no floating point fields. Reject floats rather than claim
    Python's float formatter implements ECMAScript number serialization.
    UTF-16 key ordering and unnormalized Unicode are intentional.
    """
    if value is None or type(value) is bool or type(value) is str:
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if type(value) is int:
        require(abs(value) <= 9007199254740991, 'jcs_unsafe_integer')
        return str(value)
    if type(value) is list or type(value) is tuple:
        return '[' + ','.join(jcs(x) for x in value) + ']'
    if type(value) is dict:
        require(all(type(k) is str for k in value), 'jcs_nonstring_key')
        keys = sorted(value, key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(jcs(k) + ':' + jcs(value[k]) for k in keys) + '}'
    raise PrototypeError('unsupported_jcs_value:' + type(value).__name__)

def stable(prefix, payload):
    return prefix + '_' + sha(jcs(payload).encode('utf-8'))

def unique(values):
    return [v for _, v in sorted({jcs(v): v for v in values}.items())]

def run_id(envelope):
    return stable('asrun', {k: envelope[k] for k in (
        'contract_version','taxonomy_version','dataset_version',
        'input_artifact_digests','upstream_config_digests','policy_digest')})

def group_id(run, members, label, rule):
    return stable('asp', dict(run_id=run, member_stage_ids=sorted(members),
                             semantic_label=label, purpose_rule_id=rule))

@dataclass
class Snapshot:
    stage8: dict
    stage9: dict
    receipt: dict
    provenance: dict
    digests: dict
    schema: dict
    policy_digest: str
    files: dict = field(default_factory=dict)
    indexes: dict = field(default_factory=dict)
    original_signature: str = ''

@dataclass(frozen=True)
class Proposal:
    members: tuple[str, ...]
    reasons: tuple[str, ...]
    # Identity equality is an explicit hypothesis, never assumed for all groups.
    identity_kind: str | None = None

def index(rows, key):
    require(type(rows) is list, 'required_table:' + key)
    result = {}
    for row in rows:
        require(type(row) is dict and row.get(key), 'missing_id:' + key)
        require(row[key] not in result, 'duplicate_id:' + key)
        result[row[key]] = row
    return result


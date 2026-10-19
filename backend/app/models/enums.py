"""Frozen v1 enums. Alert and chain relations deliberately have different types."""

from enum import Enum
from pydantic_core import core_schema


class ContractEnum(str, Enum):
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        def validate(value):
            if type(value) is cls:
                return value
            if type(value) is not str:
                raise ValueError(f"{cls.__name__} requires its own enum or an exact string")
            return cls(value)
        return core_schema.no_info_before_validator_function(validate, handler(source))


class SourceType(ContractEnum):
    WAZUH = "wazuh"
    AMINER = "aminer"
    SURICATA = "suricata"
    WAF = "waf"
    EDR = "edr"
    IDS = "ids"
    SIEM = "siem"
    WINDOWS_SECURITY = "windows_security"
    CLOUD_SECURITY = "cloud_security"
    OTHER = "other"


class SourceIndependence(ContractEnum):
    CONFIRMED_INDEPENDENT = "confirmed_independent"
    CONFIRMED_SAME_ORIGIN = "confirmed_same_origin"
    UNKNOWN = "unknown"


class Severity(ContractEnum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityType(ContractEnum):
    IP = "IP"
    HOST = "HOST"
    ACCOUNT = "ACCOUNT"
    SESSION = "SESSION"
    PROCESS = "PROCESS"
    URL = "URL"
    DOMAIN = "DOMAIN"
    FILE = "FILE"
    COMMAND = "COMMAND"


class Category(ContractEnum):
    UNKNOWN = "unknown"
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    WEB_ATTACK = "web_attack"
    AUTHENTICATION = "authentication"
    PROCESS_EXECUTION = "process_execution"
    COMMAND_EXECUTION = "command_execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class IncidentStatus(ContractEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class EntityRole(ContractEnum):
    MONITORED_HOST_IP = "monitored_host_ip"
    TARGET_ACCOUNT = "target_account"
    AUTHENTICATED_ACCOUNT = "authenticated_account"
    SOURCE_ACCOUNT = "source_account"
    AUDIT_ACCOUNT = "audit_account"
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    HOST = "host"
    ACCOUNT = "account"
    SESSION = "session"
    PROCESS = "process"
    PARENT_PROCESS = "parent_process"
    URL = "url"
    DOMAIN = "domain"
    FILE = "file"
    COMMAND = "command"


class AlertRelationType(ContractEnum):
    TARGET_TO_PROCESS = "target_to_process"
    PARENT_CHILD_PROCESS = "parent_child_process"
    ACCOUNT_HOST_PIVOT = "account_host_pivot"
    NETWORK_PIVOT = "network_pivot"
    SESSION_CONTINUITY = "session_continuity"


class ChainRelationType(ContractEnum):
    PROCESS_CAUSAL = "PROCESS_CAUSAL"
    REQUEST_TO_PROCESS = "REQUEST_TO_PROCESS"
    ACCOUNT_PIVOT = "ACCOUNT_PIVOT"
    NETWORK_PIVOT = "NETWORK_PIVOT"
    SESSION_FLOW = "SESSION_FLOW"


class ClaimKind(ContractEnum):
    FACT = "fact"
    INFERENCE = "inference"
    RECOMMENDATION = "recommendation"
    ATTACK_MAPPING = "attack_mapping"


class ClaimSection(ContractEnum):
    SUMMARY = "summary"
    ATTACK_PATH = "attack_path"
    RISK = "risk"
    RECOMMENDATIONS = "recommendations"
    ATTACK_MAPPING = "attack_mapping"


class GroundingStatus(ContractEnum):
    PENDING = "pending"
    VALIDATED = "validated"
    REJECTED = "rejected"


class AnalysisStatus(ContractEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class ReasonCode(ContractEnum):
    TIME_GAP = "time_gap"
    SHARED_ENTITY = "shared_entity"
    EXPLICIT_RELATION = "explicit_relation"
    BEHAVIOR_TRANSITION = "behavior_transition"
    SOURCE_COMPLEMENT = "source_complement"
    CONFLICT = "conflict"
    DUPLICATE = "duplicate"
    DIRECTION = "direction"
    CLUSTERING_GUARD = "clustering_guard"
    NODE_BASIS = "node_basis"


# Representation mapping only; this does not select a relation or its direction.
CHAIN_RELATION_MAPPING = {
    AlertRelationType.PARENT_CHILD_PROCESS: ChainRelationType.PROCESS_CAUSAL,
    AlertRelationType.TARGET_TO_PROCESS: ChainRelationType.REQUEST_TO_PROCESS,
    AlertRelationType.ACCOUNT_HOST_PIVOT: ChainRelationType.ACCOUNT_PIVOT,
    AlertRelationType.NETWORK_PIVOT: ChainRelationType.NETWORK_PIVOT,
    AlertRelationType.SESSION_CONTINUITY: ChainRelationType.SESSION_FLOW,
}
CHAIN_RELATION_PRIORITY = tuple(CHAIN_RELATION_MAPPING)

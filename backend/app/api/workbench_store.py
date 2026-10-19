"""Presentation-only persistence of already validated Explain responses.

Separate from Analysis snapshots and from the provider's generation cache.
No raw draft, credential, algorithm output or evaluation data is written here.
"""

import json
from pathlib import Path
import re
from threading import RLock

from app.ai.explanation import GroundedExplanation, load_context
from app.services.queries import QueryError
from app.services.storage import atomic_json, checked_id
from app.utils.stable_id import content_digest


def display_state(result):
    if result.generation_status == "partially_rejected":
        return "partially_rejected"
    if result.status == "available":
        return "completed"
    return "unavailable" if result.status == "unavailable" else "failed"


class ReportStore:
    def __init__(self, queries):
        self.queries = queries
        self.root = queries.root / "outputs/workbench"
        self.lock = RLock()

    def directory(self, analysis_id):
        return self.root / checked_id(analysis_id)

    def index(self, analysis_id):
        path = self.directory(analysis_id) / "index.json"
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["analysis_id"] != analysis_id or content_digest(data["items"]) != data["digest"]:
                raise ValueError("invalid_index")
            return data["items"]
        except (ValueError, KeyError, OSError):
            raise QueryError(409, "presentation_report_index_invalid") from None

    def save(self, result):
        # Only official publication envelopes, including validated fallback.
        if result.grounding_status != "validated" or result.explanation is None or result.report_json is None:
            return
        if any(c.grounding_status.value != "validated" for c in result.explanation.claims):
            raise QueryError(409, "presentation_requires_validated_report")
        self.queries.get(result.analysis_id, "incidents", result.incident_id)
        data = result.model_dump(mode="json")
        digest = content_digest(data)
        directory = self.directory(result.analysis_id)
        with self.lock:
            directory.mkdir(parents=True, exist_ok=True)
            items = self.index(result.analysis_id)
            atomic_json(directory / (result.incident_id + ".json"), {"digest": digest, "result": data})
            items[result.incident_id] = {"digest": digest, "state": display_state(result),
                "generation_status": result.generation_status, "input_digest": result.input_digest,
                "techniques": sorted({t.technique_id for t in result.attack_techniques if t.mapping_status == "validated"})}
            atomic_json(directory / "index.json", {"analysis_id": result.analysis_id,
                "items": items, "digest": content_digest(items)})

    def read(self, analysis_id, incident_id):
        # Validate snapshot/context BEFORE trusting any persisted report.
        context = load_context(self.queries, analysis_id, incident_id)
        if not re.fullmatch(r"inc_[0-9a-f]{64}", incident_id):
            raise QueryError(404, "incident_not_found")
        with self.lock:
            meta = self.index(analysis_id).get(incident_id)
            if meta is None:
                return {"analysis_id": analysis_id, "incident_id": incident_id,
                    "state": "not_generated", "read_origin": None, "result": None}
            try:
                envelope = json.loads((self.directory(analysis_id) / (incident_id + ".json")).read_text(encoding="utf-8"))
                if envelope["digest"] != meta["digest"] or content_digest(envelope["result"]) != meta["digest"]:
                    raise ValueError("digest_mismatch")
                result = GroundedExplanation.model_validate_json(json.dumps(envelope["result"]))
                if (result.analysis_id != analysis_id or result.incident_id != incident_id
                        or result.input_digest != context.input_digest or result.explanation is None
                        or result.explanation.chain_id != context.data["chain_id"]
                        or result.grounding_status != "validated"
                        or any(c.grounding_status.value != "validated" for c in result.explanation.claims)):
                    raise ValueError("report_scope_mismatch")
            except (ValueError, KeyError, OSError):
                raise QueryError(409, "presentation_report_invalid") from None
        return {"analysis_id": analysis_id, "incident_id": incident_id,
            "state": display_state(result), "read_origin": "persisted", "result": result}

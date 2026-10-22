"""Confirmed AIT-ADS v1 AMiner JSON profile; software version stays unknown."""

from app.entities.normalization import integer, text
from app.models import ProcessRef, SourceType
from .base import AlertAdapter, pick
from .wazuh import parsed_snippet


class AMinerAdapter(AlertAdapter):
    def __init__(self, config, settings):
        super().__init__(config, settings)
        if settings.format_profile != "ait_ads_v1_aminer_json" or settings.epoch_unit != "seconds" or settings.dataset_version != 1:
            raise ValueError("unsupported_aminer_format_profile")

    def extract(self, raw):
        component, log = raw.get("AnalysisComponent"), raw.get("LogData")
        if type(component) is not dict or type(log) is not dict:
            raise ValueError("invalid_aminer_structure")
        times = log.get("DetectionTimestamp")
        if type(times) is not list or not times:
            raise ValueError("missing_detection_timestamp")
        facts = {"timestamp": self.parse_time(times[-1]), "source_type": SourceType.AMINER}
        pointers = {"timestamp": "/LogData/DetectionTimestamp/" + str(len(times) - 1), "source_type": "/AnalysisComponent"}
        for name, paths in {
            "sensor": ("/AMiner/ID",), "source_record_id": ("/RecordID",),
            "rule_id": ("/AnalysisComponent/AnalysisComponentIdentifier",),
            "alert_type": ("/AnalysisComponent/AnalysisComponentType",),
            "signature": ("/AnalysisComponent/AnalysisComponentName",),
        }.items():
            pick(raw, facts, pointers, name, *paths)
        if "alert_type" not in facts or "signature" not in facts:
            raise ValueError("missing_analysis_component_identity")
        # The detector's parsed fields outrank regex supplementation. Not all
        # detectors report a flat aligned path/value vector (frequency detectors
        # also report nested path sets); those are left as raw evidence.
        paths = component.get("AffectedLogAtomPaths", [])
        values = component.get("AffectedLogAtomValues", [])
        process_fields = {}
        for index, (path, value) in enumerate(zip(paths, values)) if len(paths) == len(values) else []:
            if type(path) is not str or type(value) not in (str, int, float) or value in ("None", "", "-"):
                continue
            name = None
            if path.endswith("/host"):
                name = "host"
            elif path.endswith("/user"):
                name = "account"
            elif path.endswith("/domain"):
                name = "domain"
            elif path.endswith("/url"):
                name = "url"
            elif path.endswith("/ip"):
                name = "src_ip" if "/query/" in path else "dst_ip" if "/reply/" in path or "/forwarded/" in path else None
            elif path.endswith("/pid"):
                process_fields["pid"] = integer(value)
                pointers['process.pid'] = '/AnalysisComponent/AffectedLogAtomValues/'+str(index)
            elif path.endswith("/exe"):
                process_fields["executable"] = text(value)
                pointers['process.executable'] = '/AnalysisComponent/AffectedLogAtomValues/'+str(index)
            elif path.endswith("/comm/comm"):
                process_fields["name"] = text(value)
                pointers['process.name'] = '/AnalysisComponent/AffectedLogAtomValues/'+str(index)
            if name and name not in facts:
                facts[name] = value
                pointers[name] = "/AnalysisComponent/AffectedLogAtomValues/" + str(index)
        if process_fields:
            facts["process"], pointers["process"] = ProcessRef(**process_fields), "/AnalysisComponent/AffectedLogAtomValues"
        snippets = log.get("RawLogData", [])
        if type(snippets) is not list:
            raise ValueError("invalid_raw_log_data")
        if len(snippets) == 1:
            parsed_snippet(raw, facts, pointers, "/LogData/RawLogData/0", syslog=True)
        return facts, pointers, {"raw_severity": raw.get("Severity"), "rule_groups": [], "vendor_category": None}

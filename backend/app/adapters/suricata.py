"""Native EVE security alerts through the existing normalization/identity contract."""
from app.entities.normalization import integer, text
from app.models import SourceType
from .base import AlertAdapter, pick


class SuricataAdapter(AlertAdapter):
    def __init__(self, config, settings):
        super().__init__(config, settings)
        if settings.format_profile != "suricata_eve_v1" or settings.epoch_unit is not None:
            raise ValueError("unsupported_suricata_format_profile")

    def extract(self, raw):
        if raw.get("event_type") != "alert":
            raise ValueError("non_alert_event_type")
        metadata = raw.get("alert")
        if type(metadata) is not dict:
            raise ValueError("missing_suricata_alert")
        facts = {"timestamp": self.parse_time(raw.get("timestamp")),
                 "source_type": SourceType.SURICATA}
        pointers = {"timestamp": "/timestamp", "source_type": "/event_type"}
        for name, paths in {
            "alert_type": ("/event_type",), "src_ip": ("/src_ip",),
            "src_port": ("/src_port",), "dst_ip": ("/dest_ip", "/dst_ip"),
            "dst_port": ("/dest_port", "/dst_port"),
            "signature": ("/alert/signature",), "rule_id": ("/alert/signature_id",),
            "url": ("/http/url",), "domain": ("/http/hostname", "/tls/sni"),
            "sensor": ("/sensor",),
        }.items():
            # EVE endpoint aliases must agree; conflicting evidence is rejected.
            if name in {"dst_ip", "dst_port"}:
                values = [raw[p[1:]] for p in paths if raw.get(p[1:]) not in (None, "")]
                if len(values) == 2 and values[0] != values[1]:
                    raise ValueError("conflicting_alias:" + name)
            pick(raw, facts, pointers, name, *paths)
        if "signature" in facts and type(facts["signature"]) is not str:
            raise ValueError("invalid_signature")
        if "rule_id" in facts:
            facts["rule_id"] = str(integer(facts["rule_id"], minimum=1))
        native = metadata.get("severity")
        if native is not None and (type(native) is not int or not 1 <= native <= 255):
            raise ValueError("invalid_severity")
        return facts, pointers, {"raw_severity": native,
                                 "vendor_category": text(metadata.get("category")), "rule_groups": []}


def alert_warnings(alert):
    """Missing optional facts and unmapped priorities are explicit, never inferred."""
    warnings = ["missing_" + name for name in ("signature", "rule_id", "src_ip", "dst_ip")
                if getattr(alert, name) is None]
    if alert.severity.value == "unknown":
        warnings.append("severity_unknown")
    return tuple(warnings)

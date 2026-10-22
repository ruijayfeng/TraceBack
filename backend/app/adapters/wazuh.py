"""Wazuh alert JSON, including explicitly identified Suricata envelopes."""

import re

from app.models import ProcessRef, SourceType
from app.models.base import resolve_pointer
from app.entities.normalization import integer, text, timestamp
from .base import AlertAdapter, pick


def parsed_snippet(raw, facts, pointers, pointer, *, syslog=False):
    """Parse only a snippet already attached to this alert; never read log files."""
    try:
        snippet = resolve_pointer(raw, pointer)
    except ValueError:
        return
    if type(snippet) is not str:
        return
    def put(name, value):
        if name not in facts and value is not None:
            facts[name], pointers[name] = value, pointer
    if syslog:
        match = re.match(r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:", snippet)
        if match:
            put("host", match[1])
            if match[3]:
                put("process", ProcessRef(name=match[2], pid=int(match[3])))
    for name, pattern in (
        ("account", r"\buser=<([^>]+)>"), ("account", r"\buser[ =]([\w.@-]+)"),
        ("session", r"\bsession=<([^>]+)>"), ("src_ip", r"\brip=([^,\s]+)"),
        ("dst_ip", r"\blip=([^,\s]+)"),
    ):
        match = re.search(pattern, snippet)
        if match:
            put(name, match[1])


class WazuhAdapter(AlertAdapter):
    def __init__(self, config, settings):
        super().__init__(config, settings)
        if settings.format_profile != "wazuh_json_v1" or settings.epoch_unit is not None:
            raise ValueError("unsupported_wazuh_format_profile")

    def extract(self, raw):
        if type(raw.get("rule")) is not dict:
            raise ValueError("missing_wazuh_rule")
        facts, pointers = {}, {}
        value = pick(raw, facts, pointers, "timestamp", "/@timestamp", "/timestamp")
        facts["timestamp"] = self.parse_time(value)
        facts["source_type"], pointers["source_type"] = SourceType.WAZUH, "/rule"
        rule = raw["rule"]
        groups = rule.get("groups", [])
        data = raw.get("data", {})
        # Product identity requires vendor fields, not the input file's name.
        if "suricata" in groups and data.get("event_type") == "alert" and type(data.get("alert")) is dict:
            facts["source_type"], pointers["source_type"] = SourceType.SURICATA, "/rule/groups"
        field_paths = {
            "source_record_id": ("/id",), "sensor": ("/agent/name", "/manager/name"),
            "rule_id": ("/rule/id",), "signature": ("/data/alert/signature", "/rule/description"),
            "alert_type": ("/data/event_type", "/decoder/name"),
            "src_ip": ("/data/src_ip", "/data/srcip"), "dst_ip": ("/data/dest_ip", "/data/dstip"),
            "src_port": ("/data/src_port", "/data/srcport"), "dst_port": ("/data/dest_port", "/data/dstport"),
            # agent.name is the collector; it is not always the actual execution host.
            "host": ("/predecoder/hostname", "/data/host", "/data/hostname"),
            "account": ("/data/dstuser", "/data/srcuser", "/data/user"),
            "session": ("/data/session", "/data/audit/session"),
            "url": ("/data/http/url", "/data/url"),
            "domain": ("/data/http/hostname", "/data/dns/query/0/rrname", "/data/dns/query/rrname", "/data/tls/sni"),
            "file": ("/data/file", "/data/filename", "/data/files/0/filename"), "command": ("/data/command", "/data/audit/command"),
            "origin_namespace": ("/origin_namespace",), "origin_record_id": ("/origin_record_id",),
        }
        for name, paths in field_paths.items():
            pick(raw, facts, pointers, name, *paths)
        # Wazuh's snort decoder can put an endpoint in dstip. Split the real value.
        if ":" in str(facts.get("dst_ip", "")) and raw.get("decoder", {}).get("name") == "snort":
            match = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+):(\d+)", facts["dst_ip"])
            if match:
                facts["dst_ip"], facts["dst_port"] = match[1], match[2]
                pointers["dst_port"] = pointers["dst_ip"]
        for role, path in (("process", "/data/process"), ("parent_process", "/data/parent_process")):
            try:
                process = resolve_pointer(raw, path)
            except ValueError:
                continue
            if type(process) is not dict:
                raise ValueError("invalid_process")
            fields = {name: text(process.get(name)) for name in ("name", "executable")}
            if process.get("pid") is not None:
                fields["pid"] = integer(process["pid"])
            if process.get("start_time") is not None:
                fields["start_time"] = timestamp(process["start_time"], source_timezone=self.normalization.source_timezones.get(self.settings.source_namespace))
            facts[role], pointers[role] = ProcessRef(**fields), path
            pointers.update({role+'.'+k: path+'/'+k for k,v in fields.items() if v is not None})
        audit = data.get("audit")
        if "process" not in facts and type(audit) is dict and any(audit.get(k) for k in ("exe", "command", "pid")):
            fields = {"name": text(audit.get("command")), "executable": text(audit.get("exe"))}
            if audit.get("pid") is not None:
                fields["pid"] = integer(audit["pid"])
            facts["process"], pointers["process"] = ProcessRef(**fields), "/data/audit"
            for child, key in (('name', 'command'), ('executable', 'exe'), ('pid', 'pid')):
                if fields.get(child) is not None:
                    pointers['process.'+child] = '/data/audit/'+key
        parsed_snippet(raw, facts, pointers, "/full_log", syslog=True)
        if self.settings.semantic_profile == "wazuh_local_v1":
            from .wazuh_semantics import project_local
            project_local(raw, facts, pointers)
        level = rule.get("level")
        if type(level) in (int, float) and (not 0 <= level <= 15):
            raise ValueError("invalid_severity")
        return facts, pointers, {"raw_severity": level, "rule_groups": groups,
                                 "vendor_category": data.get("alert", {}).get("category")}

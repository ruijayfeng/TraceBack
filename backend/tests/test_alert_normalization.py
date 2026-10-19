"""Pure normalization and two-source integration, including GT access tripwires."""

import ast
from dataclasses import replace
import json
from pathlib import Path

import pytest
import yaml

from app.adapters import AMinerAdapter, WazuhAdapter
from app.config import MappingConflict, load_config, read_yaml
from app.entities.normalization import file_path, hostname, timestamp, url
from app.services.normalization import preprocess
from test_wazuh_adapter import ROOT, config, settings, synthetic_record
from test_aminer_adapter import aminer_record, aminer_settings


@pytest.mark.parametrize("value,expected", [
    ("2022-01-21T01:00:00+01:00","2022-01-21T00:00:00.000000Z"),
    ("2022-01-20T19:00:00-0500","2022-01-21T00:00:00.000000Z"),
    ("2022-01-21T00:00:00.123456789Z","2022-01-21T00:00:00.123456Z"),
])
def test_time_offset_and_precision(value,expected):
    assert timestamp(value)==expected


def test_epoch_precision_no_local_timezone():
    assert timestamp(-0.0000001,epoch_unit="seconds")=="1969-12-31T23:59:59.999999Z"
    assert timestamp(1642723200123,epoch_unit="milliseconds")=="2022-01-21T00:00:00.123000Z"
    with pytest.raises(ValueError,match="missing_timezone"):
        timestamp("2022-01-21T00:00:00")


def test_url_host_file_normalization_semantics():
    assert hostname("HOST.")=="host"
    assert hostname("host.example.com") != hostname("host")
    assert hostname("ALIAS.",{"alias":"known.example"})=="known.example"
    assert url("HTTP://EXAMPLE.COM:80/Case?x=%41&x=A#frag")=="http://example.com/Case?x=%41&x=A"
    assert url("/Path?X=A#fragment")=="/Path?X=A"
    assert file_path("C:/Folder/MiXeD", "windows")=="c:\\folder\\mixed"
    assert file_path("C:/Folder/MiXeD")=="C:/Folder/MiXeD"


@pytest.mark.parametrize("value,expected", [("//", "//"), ("///Case?x=%41#fragment", "///Case?x=%41"),
                                         ("//?x=1", "//?x=1"), ("/Case?", "/Case?")])
def test_authorityless_request_path_preserves_slashes_and_query(value, expected):
    assert url(value) == expected
    assert url(expected) == expected


def test_two_source_pipeline_outputs_and_determinism(config,tmp_path,monkeypatch):
    wazuh=WazuhAdapter(config,settings(network_namespace="synthetic.network"))
    aminer=AMinerAdapter(config,aminer_settings(network_namespace="synthetic.network"))
    wp,ap=tmp_path/"wazuh.json",tmp_path/"aminer.json"
    wp.write_text(json.dumps(synthetic_record())+"\n",encoding="utf-8")
    ap.write_text(json.dumps(aminer_record())+"\n",encoding="utf-8")
    original=Path.open
    def tripwire(path,*args,**kwargs):
        assert path.name != "labels.csv" and "evaluation" not in [p.lower() for p in path.parts]
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,"open",tripwire)
    first=preprocess([(wazuh,wp),(aminer,ap)],output_root=tmp_path)
    second=preprocess([(aminer,ap),(wazuh,wp)])
    assert first==second
    assert first.summary["total_input_alerts"]==first.summary["accepted_alert_count"]==2
    assert first.summary["rejected_alert_count"]==0
    assert (tmp_path/first.manifest["diagnostics_ref"]).is_file()
    domain=tmp_path/first.manifest["domain_ref"]
    assert len((domain/"alerts.jsonl").read_text(encoding="utf-8").splitlines())==2
    assert first.manifest["config_snapshot"]["sources"][aminer.settings.source_namespace]["generator_version"]=="unknown"


def test_pipeline_rejection_is_incomplete_and_accounted(config,tmp_path):
    adapter=WazuhAdapter(config,settings())
    path=tmp_path/"alerts.jsonl";path.write_text(json.dumps(synthetic_record())+"\n{invalid\n",encoding="utf-8")
    result=preprocess([(adapter,path)])
    assert result.summary["total_input_alerts"]==2 and result.summary["rejected_alert_count"]==1
    assert result.manifest["status"]=="incomplete" and not result.manifest["is_complete"]


def test_changed_deployment_changes_snapshot_but_not_alert_identity(config,tmp_path):
    a=settings(asset_namespace="synthetic.assets-a");b=replace(a,asset_namespace="synthetic.assets-b")
    path=tmp_path/"alerts.json";path.write_text(json.dumps(synthetic_record(data={"host":"observed-host"})),encoding="utf-8")
    first=preprocess([(WazuhAdapter(config,a),path)])
    second=preprocess([(WazuhAdapter(config,b),path)])
    assert first.analysis_id != second.analysis_id
    # Source settings do not enter alert identity; they do enter entity identity.
    assert first.alerts[0].alert_id==second.alerts[0].alert_id
    assert first.entities[0].entity_id != second.entities[0].entity_id


def test_no_dataset_branches_or_evaluation_imports_in_production():
    for path in (ROOT/"backend/app").rglob("*.py"):
        source=path.read_text(encoding="utf-8")
        assert "russellmitchell" not in source
        tree=ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                assert all(a.name.split(".")[0] != "evaluation" for a in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] != "evaluation"


def test_category_priority_and_severity_conflict(config,tmp_path):
    baseline=read_yaml(ROOT/"configs/algorithm-v0.yaml")
    category={"schema_version":"1.0","mapping_type":"category","source_type":"wazuh","default":"unknown",
              "rules":[{"id":name,"match":{"all":[{"field":"rule_id","op":"eq","value":"synthetic-rule"}]},"output":name}
                       for name in ("authentication","web_attack")]}
    severity={"schema_version":"1.0","mapping_type":"severity","source_type":"wazuh","default":"unknown","rules":[]}
    (tmp_path/"category.yaml").write_text(yaml.safe_dump(category),encoding="utf-8")
    (tmp_path/"severity.yaml").write_text(yaml.safe_dump(severity),encoding="utf-8")
    baseline["normalization"]["category_mapping_files"]=["category.yaml"]
    baseline["normalization"]["severity_mapping_files"]=["severity.yaml"]
    (tmp_path/"algorithm.yaml").write_text(yaml.safe_dump(baseline),encoding="utf-8")
    adapter=WazuhAdapter(load_config(tmp_path/"algorithm.yaml"),settings())
    alert=adapter.convert(synthetic_record())
    assert alert.category.value=="web_attack"
    provenance=alert.field_provenance["category"].transform
    assert "authentication" in provenance and "web_attack" in provenance


def test_mapping_conflicts_across_files_abort_configuration(config,tmp_path):
    baseline=read_yaml(ROOT/"configs/algorithm-v0.yaml")
    references=[]
    for name in ("low","high"):
        mapping={"schema_version":"1.0","mapping_type":"severity","source_type":"wazuh","default":"unknown",
                 "rules":[{"id":"synthetic-level","match":{"all":[{"field":"raw_severity","op":"eq","value":6}]},"output":name}]}
        (tmp_path/(name+".yaml")).write_text(yaml.safe_dump(mapping),encoding="utf-8")
        references.append(name+".yaml")
    baseline["normalization"]["category_mapping_files"]=[str(ROOT/"configs/mappings/wazuh-category.yaml")]
    baseline["normalization"]["severity_mapping_files"]=references
    (tmp_path/"algorithm.yaml").write_text(yaml.safe_dump(baseline),encoding="utf-8")
    adapter=WazuhAdapter(load_config(tmp_path/"algorithm.yaml"),settings())
    with pytest.raises(MappingConflict,match="conflicting mapping files"):
        adapter.batch([synthetic_record()])

"""Stage 1–4 contracts, using synthetic alerts only (never dataset fixtures)."""
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.adapters.base import AdapterSettings, reject_truth
from app.adapters.multisource import MultiSourceAdapter
from app.config import load_config, read_yaml
from app.models import CanonicalAlert
from app.models.base import resolve_pointer
from app.stages import load_stage_config, normalize_behavior
from app.stages.behavior import semantic_input

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def policies():
    return (load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',
                        deployment_override=ROOT/'configs/front-data-sources.yaml'),
            load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))


def adapter(policies, source):
    settings = AdapterSettings(**read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources'][source])
    return MultiSourceAdapter(policies[0], settings, source)


def edr(**extra):
    return dict(timestamp='2026-01-01T00:00:00Z', source_type='edr',
                event_id='synthetic-observation', hostname='synthetic-host',
                process_id=7, process_name='worker', executable='/opt/worker', **extra)


@pytest.mark.parametrize('priority,expected', [(1, 'high'), (2, 'medium'), (3, 'low'), (4, 'unknown')])
def test_native_suricata_priority_contract(policies, priority, expected):
    raw = dict(timestamp='2026-01-01T00:00:00Z', event_type='alert',
               alert=dict(signature='synthetic', signature_id=1, severity=priority))
    assert adapter(policies, 'ids').convert(raw).severity.value == expected


def test_edr_process_child_provenance_reaches_behavior(policies):
    raw = edr(parent_process_id=3, parent_process_name='parent',
              parent_executable='/opt/parent', command_line='worker --check')
    alert = adapter(policies, 'edr').convert(raw)
    expected = {'process.pid': '/process_id', 'process.name': '/process_name',
                'process.executable': '/executable', 'parent_process.pid': '/parent_process_id',
                'parent_process.name': '/parent_process_name',
                'parent_process.executable': '/parent_executable', 'command': '/command_line'}
    for key, pointer in expected.items():
        assert alert.field_provenance[key].raw_pointer == pointer
    fields, refs, _, _ = semantic_input(alert, policies[1])
    assert fields['pid'] == 7 and fields['process_name'] == 'worker'
    assert fields['executable'] == '/opt/worker'
    assert fields['parent_process_name'] == 'parent'
    assert fields['parent_executable'] == '/opt/parent'
    for name, pointer in refs.items():
        if name in ('pid', 'process_name', 'executable', 'parent_process_name', 'parent_executable', 'command'):
            assert fields[name] == resolve_pointer(raw, pointer)
    assert CanonicalAlert.model_validate_json(alert.canonical_json()) == alert


def test_host_executable_has_its_own_evidence(policies):
    raw = dict(timestamp='2026-01-01T00:00:00Z', source_type='host_audit',
               pid=12, executable='/bin/sh', host='synthetic-host', operation='exec')
    alert = adapter(policies, 'host_audit').convert(raw)
    fields, refs, _, _ = semantic_input(alert, policies[1])
    assert fields['executable'] == '/bin/sh' and refs['executable'] == '/executable'


@pytest.mark.parametrize('key', ['ground_truth', 'label', 'attack_label', 'attack_flag', 'is_attack',
    'malicious', 'is_malicious', 'gt', 'truth', 'expected_stage', 'expected_chain', 'expected_behavior'])
def test_truth_annotations_fail_closed_at_ingress(policies, key):
    with pytest.raises(ValueError, match='annotation_contamination'):
        adapter(policies, 'edr').convert(edr(**{key: 'synthetic-truth'}))


def test_vendor_rule_and_ui_labels_are_not_truth():
    reject_truth({'rule': {'label': 'observed rule'}, 'product': {'labels': ['observed product']},
                  'ui': {'label': 'display'}, 'rule_label': 'observed rule'})
    with pytest.raises(ValueError, match='annotation_contamination'):
        reject_truth({'metadata': {'expected_behavior': 'EXECUTION'}})


@pytest.mark.parametrize('key', ['isAttack', 'Attack-Flag', 'ground truth', 'expectedBehavior'])
def test_truth_field_spelling_aliases(key):
    with pytest.raises(ValueError, match='annotation_contamination'):
        reject_truth({key: 'synthetic-truth'})


def test_source_product_metadata_is_not_a_fake_raw_pointer(policies):
    alert = adapter(policies, 'edr').convert(edr())
    assert 'source_product' not in alert.field_provenance
    assert alert.metadata_provenance['source_product'] == 'adapter_settings.generator'
    native = adapter(policies, 'edr').convert(edr(product='Observed EDR'))
    assert native.field_provenance['source_product'].raw_pointer == '/product'
    assert 'source_product' not in native.metadata_provenance


def test_entity_noise_behavior_community_handoff_order(policies, monkeypatch):
    from app.services import alert_pipeline as pipeline
    import app.community.builder as builder
    import app.entities.extraction as entities
    from app.community import load_community_config
    a = adapter(policies, 'edr')
    rows = [edr(operation='ProcessStart'), dict(edr(operation='ProcessStart'), timestamp='2026-01-01T00:00:00.5Z')]
    events = []
    normalize = pipeline.normalize_behaviors
    def observed_behavior(alerts, *args, **kwargs):
        alerts = list(alerts)
        events.append(('behavior', len(alerts)))
        return normalize(alerts, *args, **kwargs)
    monkeypatch.setattr(pipeline, 'normalize_behaviors', observed_behavior)
    extract = entities.extract_entities
    def observed_extract(alerts, *args, **kwargs):
        events.append(('entity', len(alerts)))
        return extract(alerts, *args, **kwargs)
    monkeypatch.setattr(entities, 'extract_entities', observed_extract)
    prepared = pipeline.ingest_records([dict(source_type='edr', event=r) for r in rows],
                                       {'edr': a}, behavior_config=policies[1])
    build = builder.build_communities
    def observed_build(alerts, *args, **kwargs):
        events.append(('community', len(alerts)))
        assert len(prepared.behaviors) == 1 and prepared.behaviors[0].community_id is None
        return build(alerts, *args, **kwargs)
    def forbidden_extract(*args, **kwargs):
        raise AssertionError('⑤ repeated ② entity extraction')
    monkeypatch.setattr(builder, 'extract_entities', forbidden_extract)
    monkeypatch.setattr(builder, 'build_communities', observed_build)
    run = builder.prepare_communities(prepared, {a.settings.source_namespace: a.settings},
                                      load_community_config(ROOT/'configs/community-v1.yaml'))
    assert prepared.noise_filter.statistics['INPUT_ALERTS'] == 2
    assert prepared.noise_filter.statistics['KEPT_ALERTS'] == 1
    assert events == [('entity', 2), ('behavior', 1), ('community', 1)]
    assert len(run.alerts) == len(run.behaviors) == 1
    assert {aid for e in prepared.entities for aid in e.alert_ids} == {a.alert_id for a in prepared.alerts}


def test_unknown_is_retained_without_community(policies):
    from app.services.alert_pipeline import prepare_alerts
    a = adapter(policies, 'edr')
    alert = a.convert(edr())
    annotation = normalize_behavior(alert, policies[1])
    assert annotation.behavior == 'UNKNOWN' and annotation.community_id is None
    result = prepare_alerts([alert], behavior_config=policies[1])
    assert result.alerts == [alert] and result.behaviors == [annotation]


def test_expanded_semantic_context_and_provenance_tampering(policies):
    raw = edr(user='Alice', logon_id='session', severity='high', operation='NetworkConnection',
              src_ip='192.0.2.1', dst_ip='192.0.2.2', protocol='TCP', action='allow')
    alert = adapter(policies, 'edr').convert(raw)
    fields = semantic_input(alert, policies[1])[0]
    assert fields['severity'] == 'high' and fields['account'] == 'Alice' and fields['session'] == 'session'
    assert fields['action'] == 'allow' and fields['protocol'] == 'TCP'
    data = alert.model_dump()
    data['field_provenance']['process.name']['raw_pointer'] = '/process_id'
    with pytest.raises(ValidationError):
        CanonicalAlert.model_validate(data)


def test_web_method_and_numeric_status_reach_behavior(policies):
    raw = dict(timestamp='2026-01-01T00:00:00Z', source_type='waf', method='POST',
               status_code=403, uri='/synthetic', rule_name='Unmapped observed rule')
    alert = adapter(policies, 'waf').convert(raw)
    fields, refs, _, payload = semantic_input(alert, policies[1])
    assert fields['method'] == 'POST' and fields['status'] == 403
    assert refs['method'] == '/method' and refs['status'] == '/status_code'
    assert payload['source_metadata']['namespace'] == 'traceback.lab.waf'


def test_one_truth_contract_is_shared_and_rechecked_at_boundaries(policies):
    from app.adapters.truth import GROUND_TRUTH_FORBIDDEN_FIELDS
    from app.services.analysis import FORBIDDEN, reject_annotations
    from app.noise_filter import filter_alerts
    from app.utils.stable_id import raw_fingerprint
    assert FORBIDDEN is GROUND_TRUTH_FORBIDDEN_FIELDS
    a = adapter(policies, 'edr').convert(edr())
    raw = dict(a.raw_alert, expected_stage='synthetic-truth')
    contaminated = a.model_copy(update=dict(raw_alert=raw, raw_fingerprint=raw_fingerprint(raw)))
    for operation in (reject_annotations,):
        with pytest.raises(ValueError, match='annotation_contamination'):
            operation(raw)
    with pytest.raises(ValueError, match='annotation_contamination'):
        filter_alerts([contaminated])
    with pytest.raises(ValueError, match='annotation_contamination'):
        semantic_input(contaminated, policies[1])


def test_stage_cannot_recompute_semantics_after_community(policies, monkeypatch):
    from app.community import prepare_communities, load_community_config
    from app.stages import aggregate_stages
    import app.stages.behavior as behavior
    a = adapter(policies, 'edr')
    settings = {a.settings.source_namespace: a.settings}
    config = load_community_config(ROOT/'configs/community-v1.yaml')
    run = prepare_communities([a.convert(edr())], settings, config, behavior_config=policies[1])
    def forbidden(*args, **kwargs):
        raise AssertionError('Behavior recomputed after Community')
    monkeypatch.setattr(behavior, 'normalize_behavior', forbidden)
    result = aggregate_stages(run, settings, config, policies[1])
    assert len(result.behaviors) == 1 and result.behaviors[0].community_id is not None
    assert run.behaviors[0].community_id is None


def test_file_entry_is_read_only_and_stops_before_community(policies, tmp_path, monkeypatch):
    import json
    import app.community.builder as community
    from app.services.alert_pipeline import load_alert_pipeline
    path = tmp_path/'native.jsonl'
    raw = edr()
    before = (json.dumps(dict(source_type='edr', event=raw))+'\n').encode()
    path.write_bytes(before)
    def forbidden(*args, **kwargs):
        raise AssertionError('Stage 1–4 entry executed a later algorithm')
    monkeypatch.setattr(community, 'build_communities', forbidden)
    result = load_alert_pipeline(path)
    assert len(result.alerts) == len(result.behaviors) == 1
    assert result.alerts[0].raw_alert == raw
    assert result.entities and result.alerts[0].extraction_version == 'front-data-v1'
    assert path.read_bytes() == before and list(tmp_path.iterdir()) == [path]


def test_legacy_entries_are_explicitly_not_official():
    from app.services.analysis import PIPELINE_ROLE as analysis_role
    from app.services.front_data import PIPELINE_ROLE as front_role
    from app.services.normalization import PIPELINE_ROLE as normalization_role
    assert all('NOT_OFFICIAL_ANALYSIS_PIPELINE' in r for r in (analysis_role, front_role, normalization_role))

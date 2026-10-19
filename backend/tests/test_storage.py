"""DuckDB/Parquet UTC, nested evidence, snapshot digest and isolation tests."""

import json
import pytest

from app.correlation.edges import run_correlation
from app.services.storage import SnapshotStore, restore_config
from test_correlation_score import alert, config, configured, inputs, parent_child


def test_roundtrip_nested_raw_utc_microseconds_and_analysis_isolation(tmp_path,config):
    import duckdb
    values=[alert("micro",.000001,host="h",signature='unit\x1fseparator\n中文"' + "x"*65536),
            alert("other",.000002,host="h")]
    index,settings=inputs(values)
    result=run_correlation(list(index.alerts.values()),[],list(index.entities.values()),config,settings,output_root=tmp_path)
    store=SnapshotStore(tmp_path,result.record.analysis_id)
    for parquet in (False,True):
        loaded=list(store.read_records("alerts",parquet=parquet))
        assert loaded==list(index.alerts.values())
        assert {a.timestamp[-8:] for a in loaded}=={".000001Z",".000002Z"}
    with duckdb.connect(str(store.domain/"domain.duckdb"),read_only=True) as db:
        # SQL projects the stored instant to UTC without depending on optional
        # pytz for Python's direct TIMESTAMPTZ object conversion.
        stored_times=[row[0] for row in db.execute("SELECT event_time AT TIME ZONE 'UTC' FROM alerts").fetchall()]
        parquet_times=[row[0] for row in db.execute("SELECT event_time AT TIME ZONE 'UTC' FROM read_parquet(?)",
                                                  [str(store.domain/"alerts.parquet")]).fetchall()]
        for stamps in (stored_times,parquet_times):
            assert {stamp.microsecond for stamp in stamps}=={1,2}
            assert {stamp.isoformat()+"Z" for stamp in stamps}=={a.timestamp for a in index.alerts.values()}
    record,frequency,manifest=store.read_metadata()
    assert record==result.record and frequency["N"]==2
    assert restore_config(config.snapshot).config_hash==config.config_hash
    with pytest.raises(ValueError,match="invalid_analysis_id"):
        SnapshotStore(tmp_path,"../evaluation")
    alternate=configured(tmp_path,entity={"rarity_enabled":False})
    second=run_correlation(list(index.alerts.values()),[],list(index.entities.values()),alternate,settings,output_root=tmp_path)
    assert second.record.analysis_id!=record.analysis_id
    assert store.read_metadata()[0]==record
    (store.details/"frequency_snapshot.json").write_text('{"N":999}\n',encoding="utf-8")
    with pytest.raises(ValueError,match="frequency_digest_mismatch"):
        store.read_metadata()


def test_edge_support_pair_pointer_parquet_roundtrip(tmp_path):
    config=configured(tmp_path,entity={"rarity_enabled":False})
    index,settings=inputs(parent_child())
    result=run_correlation(list(index.alerts.values()),[],list(index.entities.values()),config,settings,output_root=tmp_path)
    store=SnapshotStore(tmp_path,result.record.analysis_id)
    for parquet in (False,True):
        assert list(store.read_records("correlation_edges",parquet=parquet,context={"alerts":index.alerts,"groups":index.groups}))==result.edges


def test_task04_all_objects_roundtrip_and_existing_snapshot_unchanged(tmp_path, config):
    from fixtures.chains.synthetic import linear_fixture
    from test_chain_reconstruction import run_fixture
    from app.services.storage import file_digest
    index, settings, _, correlation = linear_fixture(config, extra_context=True)
    original = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), config, settings, output_root=tmp_path)
    upstream = SnapshotStore(tmp_path, original.record.analysis_id)
    digests = {p.name: file_digest(p) for p in upstream.domain.iterdir()}
    result = run_fixture(index, settings, config, original, output_root=tmp_path)
    store = SnapshotStore(tmp_path, result.record.analysis_id)
    assert store.analysis_id != upstream.analysis_id
    expected = {"incidents": result.incidents, "attack_chains": result.chains,
                "chain_nodes": sorted([n for c in result.chains for n in c.nodes], key=lambda n: n.node_id),
                "chain_edges": sorted([e for c in result.chains for e in c.edges], key=lambda e: e.edge_id)}
    for parquet in (False, True):
        for kind, values in expected.items():
            assert list(store.read_records(kind, parquet=parquet)) == values
        assert store.validate_reconstruction(parquet=parquet).valid
    assert digests == {p.name: file_digest(p) for p in upstream.domain.iterdir()}
    assert upstream.read_metadata()[0] == original.record


def test_task04_reload_rejects_indexed_embedded_mismatch(tmp_path, config):
    from fixtures.chains.synthetic import linear_fixture
    from test_chain_reconstruction import run_fixture
    index, settings, _, correlation = linear_fixture(config)
    result = run_fixture(index, settings, config, correlation, output_root=tmp_path)
    store = SnapshotStore(tmp_path, result.record.analysis_id)
    # Recompute manifest on purpose: integrity must validate semantics even when
    # a malicious or buggy writer has updated content hashes successfully.
    nodes = sorted([n for c in result.chains for n in c.nodes], key=lambda n: n.node_id)
    store.write_records("chain_nodes", nodes[1:])
    store.write_metadata(result.record, index.frequency_snapshot(), result.summary)
    with pytest.raises(ValueError, match="embedded_objects_mismatch"):
        store.validate_reconstruction()

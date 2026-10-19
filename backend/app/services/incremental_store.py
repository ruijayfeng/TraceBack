"""DuckDB generation transactions, immutable publication and restart recovery."""

import json
import csv
from pathlib import Path
import zlib
import time

import duckdb

from app.services.storage import MODELS, SnapshotStore, atomic_json, parse_analysis_record
from app.utils.stable_id import content_digest


TABLES = ('canonical_identity', 'observation_identity', 'duplicate_keys',
    'duplicate_adjacency', 'dedupe_groups', 'representative_owner', 'entity_postings',
    'entity_df', 'time_postings', 'source_postings', 'semantic_postings',
    'endpoint_proposals', 'candidate_dependencies', 'candidate_priority',
    'candidate_state', 'formal_edges', 'edge_support', 'incident_membership',
    'eligible_edge_adjacency', 'triage_rule_counts', 'triage_dependencies',
    'analysis_frequency_state', 'domain_entities', 'domain_incidents', 'domain_chains')


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


class IncrementalStore:
    def __init__(self, path, config_hash):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = duckdb.connect(str(self.path))
        self.db.execute('CREATE TABLE IF NOT EXISTS workspace_meta (key VARCHAR PRIMARY KEY, payload VARCHAR)')
        self.db.execute('CREATE TABLE IF NOT EXISTS generations (generation_id VARCHAR PRIMARY KEY, payload VARCHAR)')
        for name in TABLES:
            self.db.execute(f'CREATE TABLE IF NOT EXISTS {name} (object_id VARCHAR PRIMARY KEY, payload BLOB NOT NULL)')
        row = self.db.execute("SELECT payload FROM workspace_meta WHERE key='config_hash'").fetchone()
        if row is not None and json.loads(row[0]) != config_hash:
            self.db.close()
            raise ValueError('incremental_config_mismatch')
        if row is None:
            self.db.execute("INSERT INTO workspace_meta VALUES ('config_hash', ?)", [json.dumps(config_hash)])

    def close(self):
        self.db.close()

    def head(self):
        row = self.db.execute("SELECT payload FROM workspace_meta WHERE key='head'").fetchone()
        return json.loads(row[0]) if row else None

    def load(self):
        tables = {}
        for name in TABLES:
            tables[name] = {key: json.loads(zlib.decompress(payload)) for key, payload in
                self.db.execute(f'SELECT object_id,payload FROM {name} ORDER BY object_id').fetchall()}
        return tables

    def committed_batch(self, batch_hash):
        for (payload,) in self.db.execute('SELECT payload FROM generations').fetchall():
            row = json.loads(payload)
            if row['batch_hash'] == batch_hash:
                return row
        return None

    def commit(self, tables, generation, fault=None, expected_head=None):
        """Every domain stage, reverse index and generation head share one commit."""
        started=time.perf_counter()
        self.db.execute('BEGIN TRANSACTION')
        try:
            current = self.head()
            if (current['generation_id'] if current else None) != expected_head:
                raise ValueError('incremental_concurrent_generation_retry_required')
            changed = {}
            for name in TABLES:
                old = dict(self.db.execute(f'SELECT object_id,payload FROM {name}').fetchall())
                wanted = tables[name]
                deleted = sorted(old.keys()-wanted.keys())
                if deleted:
                    self.db.execute(f'DELETE FROM {name} WHERE object_id IN (SELECT unnest(?))', [deleted])
                rows = []
                for key, value in sorted(wanted.items()):
                    encoded = zlib.compress(json_bytes(value))
                    if old.get(key) != encoded:
                        rows.append((key, encoded))
                if rows:
                    staging = self.path.parent/'transaction_rows'
                    staging.mkdir(exist_ok=True)
                    path = staging/(name+'.tsv')
                    with path.open('w',encoding='utf-8',newline='') as handle:
                        writer=csv.writer(handle,delimiter='\t',lineterminator='\n')
                        writer.writerows((key,payload.hex()) for key,payload in rows)
                    max_line=max(len(key.encode('utf-8'))+len(payload)*2+32 for key,payload in rows)
                    self.db.execute(f"INSERT OR REPLACE INTO {name} SELECT object_id,from_hex(encoded) "
                        "FROM read_csv(?,header=false,delim='\\t',auto_detect=false,quote='\"',escape='\"',"
                        "columns={'object_id':'VARCHAR','encoded':'VARCHAR'},max_line_size=?)",[str(path),max_line])
                changed[name] = {'upserts': len(rows), 'deletes': len(deleted)}
                if fault:
                    fault('table:'+name)
            generation['writes'] = changed
            elapsed=time.perf_counter()-started
            generation['stats']['transaction_staging_seconds']=elapsed
            generation['stats']['total_time']+=elapsed
            generation['record']['metrics']['total_runtime_seconds']=generation['stats']['total_time']
            self.db.execute('INSERT INTO generations VALUES (?,?)',
                [generation['generation_id'], json_bytes(generation).decode()])
            self.db.execute("INSERT OR REPLACE INTO workspace_meta VALUES ('head',?)",
                [json_bytes(generation).decode()])
            if fault:
                fault('before_commit')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        if fault:
            fault('after_commit')
        return generation

    def publish(self, root, generation, tables, fault=None):
        """A committed head is the sole publication source; interrupted exports recover.

        Publication uses a generation-specific staging root and publishes the
        manifest last. Existing snapshots are never written through this path.
        """
        root = Path(root).resolve()
        identity = generation['analysis_id']
        final = SnapshotStore(root, identity)
        if (final.details/'manifest.json').exists():
            _, _, manifest = final.read_metadata()
            published_generation=manifest.get('incremental_generation',manifest['summary']).get('generation_id')
            if published_generation != generation['generation_id']:
                raise ValueError('immutable_snapshot_already_exists')
            atomic_json(self.path.parent/'published_head.json', {'analysis_id':identity,
                'generation_id':generation['generation_id'], 'digest':content_digest(generation['record'])})
            return identity
        staging = self.path.parent/'publication'/generation['generation_id']
        store = SnapshotStore(staging, identity)
        if final.domain.exists():
            # Domain movement only happens after staging is complete. Resume
            # those exact bytes: rebuilding run timestamps or Parquet here
            # would disagree with the already moved immutable domain files.
            staged_manifest=store.details/'manifest.json'
            if not staged_manifest.exists():
                raise ValueError('incremental_publication_staging_missing')
            manifest=json.loads(staged_manifest.read_text(encoding='utf-8'))
            published_generation=manifest.get('incremental_generation',manifest['summary']).get('generation_id')
            if published_generation!=generation['generation_id']:
                raise ValueError('incremental_publication_generation_mismatch')
            final.details.parent.mkdir(parents=True,exist_ok=True)
            if not final.details.exists():
                store.details.replace(final.details)
            else:
                for source in sorted(store.details.iterdir(),key=lambda p:(p.name=='manifest.json',p.name)):
                    source.replace(final.details/source.name)
            final.read_metadata()
            atomic_json(self.path.parent/'published_head.json', {'analysis_id':identity,
                'generation_id':generation['generation_id'], 'digest':content_digest(generation['record'])})
            return identity
        # Safe to retry only this unpublished generation-specific staging area.
        mapping = {'alerts':'canonical_identity', 'entities':'domain_entities',
            'dedupe_groups':'dedupe_groups', 'correlation_edges':'formal_edges',
            'incidents':'domain_incidents', 'attack_chains':'domain_chains'}
        for kind, table in mapping.items():
            store.write_records(kind, tables[table].values())
        chains = list(tables['domain_chains'].values())
        store.write_records('chain_nodes', [n for c in chains for n in c['nodes']])
        store.write_records('chain_edges', [e for c in chains for e in c['edges']])
        record = parse_analysis_record(generation['record'],generation.get('execution'))
        with store.diagnostics_writer() as sink:
            for row in generation['audit']:
                sink(row)
            sink({'stage':'incremental_generation', 'generation_id':generation['generation_id'],
                'parent_analysis_id':generation['parent_analysis_id'], 'batch_hash':generation['batch_hash'],
                'cached_pair_evidence':'candidate_state in committed workspace; immutable parent snapshots retained',
                'stats':generation['stats']})
        if generation.get('execution'):
            from app.services.analysis import now
            timestamp=now()
            stats=generation['stats']
            run={'analysis_id':identity,'status':record.status.value,'is_complete':record.is_complete,
                'created_at':timestamp,'started_at':timestamp,'completed_at':timestamp,
                'config_hash':record.config_hash,'config_digest':record.config_digest,'mapping_digest':record.mapping_digest,
                'config_snapshot':record.config_snapshot,'algorithm_version':record.algorithm_version,
                'dataset_digest':record.dataset_digest,'config_version':record.config_snapshot['algorithm']['version'],
                'inputs':[],'input_files':[], 'counts':{'canonical_alert_count':record.metrics.alert_count,
                    'representative_count':record.metrics.representative_count,'candidate_pair_count':record.metrics.candidate_pair_count,
                    'correlation_edge_count':len(tables['formal_edges']),'incident_count':len(tables['domain_incidents']),
                    'attack_chain_count':len(tables['domain_chains']),'chain_node_count':sum(len(c['nodes']) for c in chains),
                    'chain_edge_count':sum(len(c['edges']) for c in chains)},
                'runtime':{'total_seconds':stats['total_time']},'metrics':record.metrics.model_dump(mode='json'),
                'errors':record.errors,'warnings':[],'incomplete_reason':record.incomplete_reason,
                'candidate_contract_version':'v1.1','candidate_truncated':record.candidate_truncated,
                'state_history':['queued','running',record.status.value],
                'diagnostics_ref':record.diagnostics_ref,'frequency_snapshot_ref':record.frequency_snapshot_ref,
                'manifest_ref':f'outputs/analyses/{identity}/manifest.json'}
            atomic_json(store.domain/'run.json',run)
            store.write_metadata(record,generation['frequency'],run,execution=generation['execution'])
            manifest=json.loads((store.details/'manifest.json').read_text(encoding='utf-8'))
            manifest['incremental_generation']={k:generation[k] for k in
                ('parent_analysis_id','batch_hash','config_hash','algorithm_version','generation_id','stats')}
            atomic_json(store.details/'manifest.json',manifest)
        else:
            store.write_metadata(record, generation['frequency'], generation)
        if fault:
            fault('before_publication')
        final.domain.parent.mkdir(parents=True, exist_ok=True)
        final.details.parent.mkdir(parents=True, exist_ok=True)
        # An interrupted move can leave domain complete but details unpublished.
        if not final.domain.exists():
            store.domain.replace(final.domain)
        if fault:
            fault('after_domain_publication')
        if not final.details.exists():
            store.details.replace(final.details)
        elif not (final.details/'manifest.json').exists():
            for source in sorted(store.details.iterdir(),key=lambda p:(p.name=='manifest.json',p.name)):
                source.replace(final.details/source.name)
        final.read_metadata()
        if fault:
            fault('after_manifest_publication')
        atomic_json(self.path.parent/'published_head.json', {'analysis_id':identity,
            'generation_id':generation['generation_id'], 'digest':content_digest(generation['record'])})
        return identity

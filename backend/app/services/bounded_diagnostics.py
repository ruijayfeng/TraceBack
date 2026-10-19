"""Streaming diagnostic observation only; never changes scoring or admission."""

from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import duckdb


BATCH = 256
FILE_LIMIT = 512 * 1024 * 1024
JSON_LIMIT = 64 * 1024 * 1024


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def sql_literal(value):
    # Data-only SQL VALUES avoids this host's costly parameter binding. Always
    # double SQL apostrophes, including JSON strings and Windows file paths.
    if value is None:
        return 'NULL'
    if isinstance(value,str):
        return "'"+value.replace("'","''")+"'"
    if type(value) in (int,float):
        return repr(value)
    raise TypeError('unsupported_diagnostic_column')


class ColumnarStream:
    """One bounded in-memory batch, independent compressed Parquet parts."""
    def __init__(self, directory, columns):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.columns, self.rows, self.parts, self.bytes, self.row_bytes = columns, [], 0, 0, 0
        self.db = duckdb.connect(':memory:')
        self.db.execute('SET threads=1')
        self.db.execute('CREATE TABLE batch (' + columns + ')')

    def add(self, row):
        self.rows.append(row)
        self.row_bytes += sum(len(v.encode('utf8')) for v in row if isinstance(v,str))
        if len(self.rows) >= BATCH or self.row_bytes >= 8*1024*1024:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        self.db.execute('INSERT INTO batch VALUES '+','.join(
            '('+','.join(sql_literal(v) for v in row)+')' for row in self.rows))
        part = self.directory / f'{self.parts:06d}.parquet'
        self.db.execute('COPY batch TO '+sql_literal(str(part))+' (FORMAT PARQUET, COMPRESSION ZSTD)')
        size = part.stat().st_size
        if size > FILE_LIMIT:
            raise ValueError('diagnostic_part_size_guard')
        self.bytes += size
        self.parts += 1
        self.db.execute('DROP TABLE batch')
        self.db.execute('CREATE TABLE batch ('+self.columns+')')
        self.rows.clear()
        self.row_bytes = 0

    def close(self):
        self.flush()
        self.db.close()


class DiskCandidates:
    def __init__(self, directory, count):
        self.directory, self.count = directory, count

    def __len__(self):
        return self.count

    def __iter__(self):
        from app.correlation.candidates import CandidatePair, CandidateEvidence
        for part in sorted(self.directory.glob('*.parquet')):
            db = duckdb.connect(':memory:')
            try:
                db.execute('SET threads=1')
                cursor = db.execute('SELECT payload FROM read_parquet('+sql_literal(str(part))+') ORDER BY ordinal')
                while batch := cursor.fetchmany(BATCH):
                    for (payload,) in batch:
                        row = json.loads(payload)
                        evidence = []
                        for e in row['evidence']:
                            for key in ('member_ids', 'relation_facts'):
                                e[key] = tuple(e[key])
                            if e['override'] is not None:
                                e['override'] = tuple(e['override'])
                            evidence.append(CandidateEvidence(**e))
                        rank = row['priority']
                        rank[-1] = tuple(rank[-1])
                        yield CandidatePair(row['source_alert_id'], row['target_alert_id'],
                            tuple(row['channels']), tuple(evidence), tuple(rank))
            finally:
                db.close()


class BoundedDiagnostics:
    """Exact counters plus deterministic first-in-order bounded rejection samples."""
    def __init__(self, details, handle):
        self.details, self.handle = Path(details), handle
        self.decisions = ColumnarStream(self.details/'candidate_decisions',
            'source_id VARCHAR, target_id VARCHAR, decision VARCHAR, rule_id VARCHAR, evidence_decision VARCHAR, score DOUBLE, edge_id VARCHAR')
        self.samples = ColumnarStream(self.details/'candidate_samples', 'categories VARCHAR, payload VARCHAR')
        self.counts, self.rejections, self.family, self.network = Counter(), Counter(), Counter(), Counter()
        self.gates, self.sources, self.member_sources, self.flow_roles = Counter(), Counter(), Counter(), Counter()
        self.reliability, self.histogram, self.guards, self.sample_counts = Counter(), Counter(), Counter(), Counter()
        self.candidate_family, self.candidate_gates, self.guard_rejections = Counter(), Counter(), Counter()
        self.current, self.best, self.valid_best = None, None, None
        self.index = None
        self.overflow = None
        self.entity_values = {}
        self.json_bytes, self.sample_raw_bytes, self.sample_guard = 0, 0, False

    def prepare_candidates(self, index, candidates):
        self.index = index
        stream = ColumnarStream(self.details/'candidate_batches', 'ordinal BIGINT, payload VARCHAR')
        count = len(candidates.pairs)
        for ordinal, pair in enumerate(candidates.pairs):
            stream.add((ordinal, dumps(asdict(pair))))
        stream.close()
        candidates.pairs = DiskCandidates(stream.directory, count)

    @staticmethod
    def bucket(score):
        if score is None:
            return 'no_valid_member_pair'
        if score == 1:
            return '{1.00}'
        bounds = (0, .1, .2, .3, .4, .5, .6, .65, .7, .8, .9, 1)
        return next(f'[{a:.2f},{b:.2f})' for a,b in zip(bounds,bounds[1:]) if a <= score < b)

    def write(self, row, essential=False):
        data = dumps(row)+'\n'
        size = len(data.encode('utf8'))
        if essential and self.json_bytes + size > FILE_LIMIT:
            if self.overflow is None:
                self.overflow = ColumnarStream(self.details/'essential_diagnostic_overflow','payload VARCHAR')
            self.overflow.add((data,))
        elif essential or self.json_bytes + size <= JSON_LIMIT:
            self.handle.write(data)
            self.json_bytes += size
        else:
            self.counts['general_records_aggregated_after_size_guard'] += 1

    def __call__(self, row):
        stage = row.get('stage', 'unspecified')
        self.counts[stage] += 1
        if stage == 'candidate':
            self.current, self.best, self.valid_best = row, None, None
            return
        if stage == 'member_score':
            ev = row['evidence']['evidence_v2']
            self.histogram[('member',self.bucket(row['score']))] += 1
            self.gates[(ev['decision'],ev['gate_reason'])] += 1
            self.network[(ev['network_diagnostic'],ev['network_continuity_valid'])] += 1
            self.counts['duplicate_observation_member'] += int(ev['duplicate_observation_risk'])
            self.counts['metadata_dominated_member'] += int(ev['metadata_dominated'])
            self.guard_rejections.update(row.get('rejection_codes',()))
            for fact in ev['evidence']:
                self.family[(fact['family'],fact['role'])] += 1
            for feature in ev['entity_reliability']:
                self.reliability[(feature['entity_id'],feature['hot'])] += 1
                values = self.entity_values.setdefault(feature['entity_id'],dict(count=0,min=1.,max=0.,sum=0.))
                values['count'] += 1
                values['min'] = min(values['min'],feature['reliability'])
                values['max'] = max(values['max'],feature['reliability'])
                values['sum'] += feature['reliability']
            a,b = (self.index.alerts[x] for x in row['support_pair'])
            self.member_sources[(' ↔ '.join(sorted((a.source_namespace,b.source_namespace))),ev['decision'],ev['gate_reason'])] += 1
            same_src = a.src_ip is not None and a.src_ip == b.src_ip
            same_dst = a.dst_ip is not None and a.dst_ip == b.dst_ip
            role = 'src_src_only' if same_src and not same_dst else 'dst_dst_only' if same_dst and not same_src else 'same_local_endpoint_proxy' if any(x.src_ip and x.src_ip==x.dst_ip for x in (a,b)) else 'other'
            self.flow_roles[role] += 1
            key = (-row['score'],a.timestamp,b.timestamp,*row['support_pair'])
            if self.best is None or key < self.best[0]:
                self.best = (key,row)
            if row['valid'] and (self.valid_best is None or key < self.valid_best[0]):
                self.valid_best = (key,row)
            return
        if stage == 'correlation_decision':
            pair = row['support_key']
            self.counts[row['decision']] += 1
            self.histogram[('selected_valid_candidate',self.bucket(row['score']))] += 1
            self.rejections[(row['rule_id'],row.get('evidence_decision',''))] += int(row['decision']=='reject')
            sources = ' ↔ '.join(sorted(self.index.alerts[x].source_namespace for x in pair))
            self.sources[(sources,row['decision'])] += 1
            self.decisions.add((*pair,row['decision'],row['rule_id'],row.get('evidence_decision'),row['score'],row.get('edge_id')))
            if self.best:
                chosen = (self.valid_best or self.best)[1]
                ev = chosen['evidence']['evidence_v2']
                self.histogram[('candidate',self.bucket(chosen['score']))] += 1
                self.candidate_gates[(ev['decision'],ev['gate_reason'])] += 1
                self.counts['duplicate_observation_candidate'] += int(ev['duplicate_observation_risk'])
                self.counts['metadata_dominated_candidate'] += int(ev['metadata_dominated'])
                self.counts['high_frequency_entity_candidate'] += int(any(f['hot'] for f in ev['entity_reliability']))
                self.counts['valid_network_continuity_candidate'] += int(ev['network_continuity_valid'])
                for fact in ev['evidence']:
                    self.candidate_family[(fact['family'],fact['role'])] += 1
            if row['decision'] == 'accept':
                self.write(row,essential=True)
            elif self.best:
                chosen = (self.valid_best or self.best)[1]
                ev = chosen['evidence']['evidence_v2']
                categories = ['reason:'+row['rule_id']+':'+ev['decision']+':'+ev['gate_reason']]
                if .60 <= chosen['score'] < .70:
                    categories.append('near_threshold')
                if ev['duplicate_observation_risk']:
                    categories.append('duplicate_observation')
                if ev['network_diagnostic'] in ('local_host_observation','no_scoped_endpoint_bridge','endpoint_equality_without_direction_context','endpoint_bridge_without_independent_flow_context'):
                    categories.append('invalid_network_continuity')
                if any(f['hot'] for f in ev['entity_reliability']):
                    categories.append('high_frequency_entity')
                if ev['metadata_dominated']:
                    categories.append('metadata_dominated')
                if self.index.alerts[chosen['support_pair'][0]].source_namespace != self.index.alerts[chosen['support_pair'][1]].source_namespace:
                    categories.append('cross_source')
                if 'flow' in ev['network_diagnostic']:
                    categories.append('network_context')
                eligible = [c for c in categories if self.sample_counts[c] < (2000 if c=='near_threshold' else 500)]
                if eligible and not self.sample_guard:
                    payload = dumps({'candidate':self.current,'member':chosen,'decision':row})
                    size = len(payload.encode('utf8'))
                    if self.sample_raw_bytes + size > FILE_LIMIT:
                        self.sample_guard = True
                    else:
                        self.samples.add((dumps(eligible),payload))
                        self.sample_raw_bytes += size
                        self.sample_counts.update(eligible)
            self.current, self.best, self.valid_best = None, None, None
            return
        if stage == 'clustering':
            self.guards[(row['decision'],row['rule_id'])] += 1
        if stage == 'targets':
            return
        self.write(row)

    @staticmethod
    def rows(counter, keys):
        return [dict(zip(keys, key if isinstance(key,tuple) else (key,)),count=count) for key,count in sorted(counter.items())]

    def close(self):
        self.decisions.close()
        self.samples.close()
        result = dict(version='bounded-diagnostics-v1', exact=True, batch_size=BATCH,
            counts=dict(self.counts), rejection_counts=self.rows(self.rejections,('rule_id','evidence_decision')),
            evidence_family_statistics=self.rows(self.family,('family','role')),
            candidate_evidence_family_statistics=self.rows(self.candidate_family,('family','role')),
            network_statistics=self.rows(self.network,('diagnostic','valid')),
            gate_statistics=self.rows(self.gates,('decision','gate_reason')),
            candidate_gate_statistics=self.rows(self.candidate_gates,('decision','gate_reason')),
            member_guard_rejections=self.rows(self.guard_rejections,('reason',)),
            source_candidate_decisions=self.rows(self.sources,('source_pair','decision')),
            member_source_decisions=self.rows(self.member_sources,('source_pair','decision','gate_reason')),
            flow_role_statistics=self.rows(self.flow_roles,('diagnostic',)),
            entity_reliability_statistics=self.rows(self.reliability,('entity_id','hot')),
            entity_reliability_values=self.entity_values,
            score_histogram=self.rows(self.histogram,('population','bucket')),
            clustering_guards=self.rows(self.guards,('decision','rule_id')),
            sample_counts=dict(self.sample_counts), sample_raw_bytes=self.sample_raw_bytes,
            sample_size_guard_triggered=self.sample_guard,
            policy=dict(rejection_reason=500,near_threshold=2000,duplicate_observation=500,
                invalid_network_continuity=500,high_frequency_entity=500,metadata_dominated=500,
                parquet_part_bytes_max=FILE_LIMIT,json_general_bytes_max=JSON_LIMIT))
        path = self.details/'bounded_diagnostics.json'
        path.write_text(dumps(result)+'\n',encoding='utf8')
        self.write({'stage':'bounded_diagnostics_summary','summary':result},essential=True)
        if self.overflow is not None:
            self.overflow.close()

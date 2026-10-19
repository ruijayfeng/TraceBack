"""Execution storage only: validated alerts, lazy exact raw JSON, bounded LRU.

No domain schema, algorithm config, identity or decision lives in this module.
The raw spill is private to a run and removed after publication or failure.
"""
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
import json
from pathlib import Path
import shutil
import sqlite3
import pickle
import zlib

from app.models import CanonicalAlert

IMPLEMENTATION_VERSION = 'capacity-v4.2-execution-4'
_EXECUTION = ContextVar('bounded_execution', default=None)


@contextmanager
def bounded_execution(directory):
    state = SpillState(directory)
    token = _EXECUTION.set(state)
    try:
        yield state
    finally:
        _EXECUTION.reset(token)
        state.close()


def execution_state():
    return _EXECUTION.get()


class BoundedCache(OrderedDict):
    def __init__(self, limit=4096):
        super().__init__()
        self.limit, self.evictions = limit, 0

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.move_to_end(key)
        while len(self) > self.limit:
            self.popitem(last=False)
            self.evictions += 1


class PackedAlert(CanonicalAlert):
    """Internal validated model with disk raw accessor; public dumps are identical."""
    def __getattribute__(self, name):
        if name == 'raw_alert':
            private = object.__getattribute__(self, '__pydantic_private__')
            if private and '_raw_locator' in private:
                state, offset, size = private['_raw_locator']
                return state.raw(offset, size)
        return super().__getattribute__(name)

    def model_dump(self, *args, **kwargs):
        data = super().model_dump(*args, **kwargs)
        if 'raw_alert' in data:
            data['raw_alert'] = self.raw_alert
        return data

    @classmethod
    def model_validate(cls, *args, **kwargs):
        return CanonicalAlert.model_validate(*args, **kwargs)


class AlertMap(Mapping):
    def __init__(self, state):
        self.state, self.records = state, {}
    def __getitem__(self, key):
        offset, size = self.records[key]
        return self.state.canonical(offset, size)
    def __iter__(self):
        return iter(self.records)
    def __len__(self):
        return len(self.records)
    def __contains__(self, key):
        return key in self.records
    def keys(self):
        return self.records.keys()
    def sorted(self):
        self.records = dict(sorted(self.records.items()))
        return self
    def add(self, alert):
        if alert.alert_id in self.records:
            if self[alert.alert_id].canonical_json() != alert.canonical_json():
                raise ValueError('same_alert_id_conflicting_content')
            return
        packed = self.state.pack(alert)
        payload = zlib.compress(pickle.dumps((packed.__dict__, packed.model_fields_set,
            packed.__pydantic_private__['_raw_locator'][1:]), protocol=5), 1)
        handle = self.state.canonical_handle
        handle.seek(0, 2)
        offset = handle.tell()
        handle.write(payload)
        self.records[alert.alert_id] = (offset, len(payload))
    def sequence(self):
        self.sorted()
        return AlertSequence(self)


class AlertSequence(Sequence):
    def __init__(self, mapping):
        self.mapping = mapping
        self.keys = tuple(mapping)
    def __iter__(self):
        return iter(self.mapping.values())
    def __len__(self):
        return len(self.mapping)
    def __getitem__(self, index):
        if isinstance(index, slice):
            return tuple(self.mapping[key] for key in self.keys[index])
        return self.mapping[self.keys[index]]


class SpillState:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        if self.directory.resolve() != self.directory:
            raise ValueError('redirected_execution_spill')
        self.directory.mkdir(parents=True, exist_ok=False)
        self.handle = (self.directory/'raw.bin').open('w+b')
        self.canonical_handle = (self.directory/'canonical.bin').open('w+b')
        self.canonical_cache = BoundedCache(512)
        self.cache = BoundedCache(128)
        self.provenance = BoundedCache(4096)
        self.connections = []
        self.counter = 0
        self.packed_count = 0
    def raw(self, offset, size):
        if hasattr(self,'resource_check'):
            self.resource_check()
        if offset not in self.cache:
            self.handle.seek(offset)
            self.cache[offset] = json.loads(zlib.decompress(self.handle.read(size)))
        return self.cache[offset]
    def canonical(self, offset, size):
        if hasattr(self, 'resource_check'):
            self.resource_check()
        if offset not in self.canonical_cache:
            self.canonical_handle.seek(offset)
            fields, fields_set, locator = pickle.loads(zlib.decompress(self.canonical_handle.read(size)))
            packed = PackedAlert.model_construct(_fields_set=fields_set, **fields)
            object.__setattr__(packed, '__pydantic_private__', {'_raw_locator': (self, *locator)})
            self.canonical_cache[offset] = packed
        return self.canonical_cache[offset]
    def pack(self, alert):
        if hasattr(self,'resource_check'):
            self.resource_check()
        if isinstance(alert, PackedAlert) and alert.__pydantic_private__['_raw_locator'][0] is self:
            return alert
        # Only already fully validated CanonicalAlert instances can be packed.
        if type(alert) is not CanonicalAlert:
            alert = CanonicalAlert.model_validate(alert.model_dump())
        payload = zlib.compress(json.dumps(alert.raw_alert, ensure_ascii=False,
            separators=(',', ':'), allow_nan=False).encode('utf8'), 1)
        self.handle.seek(0, 2)
        offset = self.handle.tell()
        self.handle.write(payload)
        self.packed_count += 1
        if self.packed_count % 10000 == 0 and hasattr(self,'progress'):
            self.progress(dict(stage='raw_spill',objects_written=self.packed_count,
                raw_spill_bytes=self.handle.tell(),cache_objects=len(self.cache)))
        fields = dict(alert.__dict__)
        fields['raw_alert'] = None
        fields['field_provenance'] = dict(fields['field_provenance'])
        for name, p in fields['field_provenance'].items():
            key = (p.raw_pointer, p.transform)
            if key not in self.provenance:
                self.provenance[key] = p
            fields['field_provenance'][name] = self.provenance[key]
        packed = PackedAlert.model_construct(_fields_set=alert.model_fields_set, **fields)
        object.__setattr__(packed, '__pydantic_private__', {'_raw_locator':(self,offset,len(payload))})
        return packed
    def alerts(self):
        return AlertMap(self)
    def database(self):
        self.counter += 1
        db = sqlite3.connect(self.directory/f'state-{self.counter}.sqlite')
        db.execute('PRAGMA cache_size=-8192')
        db.execute('PRAGMA temp_store=FILE')
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('PRAGMA synchronous=OFF')
        # Disposable run-private databases, never accepted snapshots.
        self.connections.append(db)
        return db
    def close(self):
        for db in self.connections:
            db.close()
        self.handle.close()
        self.canonical_handle.close()
        self.canonical_cache.clear()
        if hasattr(self, 'posting_block_cache'):
            self.posting_block_cache.clear()
        self.cache.clear()
        self.provenance.clear()
        if self.directory.resolve() != self.directory or self.directory.is_symlink():
            raise ValueError('redirected_execution_spill_cleanup')
        shutil.rmtree(self.directory)


class DiskMasks(Mapping):
    """Exact arbitrary-width bitset rows, compressed on disk, small SQLite cache."""
    def __init__(self, db, name):
        self.db, self.name = db, name
        db.execute(f'CREATE TABLE {name} (pos INTEGER PRIMARY KEY, value BLOB)')
    def __getitem__(self, pos):
        row = self.db.execute(f'SELECT value FROM {self.name} WHERE pos=?',(pos,)).fetchone()
        if row is None:
            raise KeyError(pos)
        return int.from_bytes(zlib.decompress(row[0]), 'little')
    def __setitem__(self, pos, value):
        blob = zlib.compress(value.to_bytes((value.bit_length()+7)//8, 'little'),1)
        self.db.execute(f'INSERT OR REPLACE INTO {self.name} VALUES (?,?)',(pos,blob))
    def __iter__(self):
        return (row[0] for row in self.db.execute(f'SELECT pos FROM {self.name} ORDER BY pos'))
    def __len__(self):
        return self.db.execute(f'SELECT count(*) FROM {self.name}').fetchone()[0]
    def items(self):
        for pos, blob in self.db.execute(f'SELECT pos,value FROM {self.name} ORDER BY pos'):
            yield pos, int.from_bytes(zlib.decompress(blob),'little')
    def values(self):
        return (value for _,value in self.items())


class DiskVector:
    def __init__(self, rows, count):
        self.rows, self.count = rows, count
    def __getitem__(self, pos):
        return self.rows.get(pos,0)
    def __setitem__(self, pos, value):
        self.rows[pos] = value
    def __iter__(self):
        rows = iter(self.rows.items())
        current = next(rows,None)
        for pos in range(self.count):
            if current is not None and current[0] == pos:
                yield current[1]
                current = next(rows,None)
            else:
                yield 0


class DiskObjects(Mapping):
    """Private typed execution values; pickle never reads user-provided data."""
    def __init__(self, db, name, factory=None):
        self.db, self.name, self.factory = db, name, factory
        db.execute(f'CREATE TABLE {name} (key TEXT PRIMARY KEY, value BLOB)')
    @staticmethod
    def encode(key):
        return json.dumps(key, separators=(',', ':'))
    def __getitem__(self, key):
        row = self.db.execute(f'SELECT value FROM {self.name} WHERE key=?',(self.encode(key),)).fetchone()
        if row is None:
            if self.factory is not None:
                return self.factory()
            raise KeyError(key)
        return pickle.loads(row[0])
    def __contains__(self, key):
        return self.db.execute(f'SELECT 1 FROM {self.name} WHERE key=?',(self.encode(key),)).fetchone() is not None
    def __setitem__(self, key, value):
        self.db.execute(f'INSERT OR REPLACE INTO {self.name} VALUES (?,?)',
            (self.encode(key),pickle.dumps(value,protocol=5)))
    def __iter__(self):
        return (tuple(json.loads(row[0])) for row in self.db.execute(f'SELECT key FROM {self.name} ORDER BY key'))
    def __len__(self):
        return self.db.execute(f'SELECT count(*) FROM {self.name}').fetchone()[0]
    def items(self):
        for key,value in self.db.execute(f'SELECT key,value FROM {self.name} ORDER BY key'):
            yield tuple(json.loads(key)),pickle.loads(value)

    def values(self):
        return (v for _,v in self.items())


class DiskList(Sequence):
    def __init__(self, db, name):
        self.db, self.name, self.count = db, name, 0
        db.execute(f'CREATE TABLE {name} (ordinal INTEGER PRIMARY KEY, value BLOB)')
    def append(self, value):
        self.db.execute(f'INSERT INTO {self.name} VALUES (?,?)',
            (self.count,pickle.dumps(value,protocol=5)))
        self.count += 1
    def __len__(self):
        return self.count
    def __getitem__(self, ordinal):
        if ordinal < 0:
            ordinal += self.count
        row = self.db.execute(f'SELECT value FROM {self.name} WHERE ordinal=?',(ordinal,)).fetchone()
        if row is None:
            raise IndexError(ordinal)
        return pickle.loads(row[0])
    def __iter__(self):
        for row in self.db.execute(f'SELECT value FROM {self.name} ORDER BY ordinal'):
            yield pickle.loads(row[0])


class DiskPairs(Sequence):
    def __init__(self, objects):
        self.objects = objects
    def __len__(self):
        return len(self.objects)
    def __iter__(self):
        return self.objects.values()
    def __getitem__(self, ordinal):
        for pos,item in enumerate(self):
            if pos == ordinal:
                return item
        raise IndexError(ordinal)


class DiskPairObjects(DiskObjects):
    """Exact run-local integer pair identity plus lossless compressed payload.

    Representative ordinals follow lexical Stable ID order. SQLite signed
    integers are safe while N <= 2**31; the checked bound is execution-only.
    Public candidate/evidence IDs always remain the original Stable IDs.
    """
    def __init__(self, db, name, index, factory=None):
        if index.N > 2**31:
            raise ValueError('packed_pair_ordinal_out_of_range')
        self.db, self.name, self.factory = db, name, factory
        self.positions, self.representatives = index.positions, index.representatives
        db.execute(f'CREATE TABLE {name} (key INTEGER PRIMARY KEY, value BLOB)')

    def encode(self, key):
        a, b = (self.positions[i] for i in key)
        if a >= b:
            raise ValueError('noncanonical_pair_key')
        return (a << 32) | b

    def decode(self, key):
        return self.representatives[key >> 32], self.representatives[key & 0xffffffff]

    def __getitem__(self, key):
        row = self.db.execute(f'SELECT value FROM {self.name} WHERE key=?', (self.encode(key),)).fetchone()
        if row is None:
            if self.factory is not None:
                return self.factory()
            raise KeyError(key)
        return pickle.loads(zlib.decompress(row[0]))

    def __setitem__(self, key, value):
        payload = zlib.compress(pickle.dumps(value, protocol=5), 1)
        self.db.execute(f'INSERT OR REPLACE INTO {self.name} VALUES (?,?)', (self.encode(key), payload))

    def __iter__(self):
        return (self.decode(row[0]) for row in self.db.execute(f'SELECT key FROM {self.name} ORDER BY key'))

    def items(self):
        for key, payload in self.db.execute(f'SELECT key,value FROM {self.name} ORDER BY key'):
            yield self.decode(key), pickle.loads(zlib.decompress(payload))


class DiskScalarObjects(Mapping):
    """Private immutable fact metadata with exact scalar keys and bounded LRU."""
    def __init__(self, db, name, limit=4096):
        self.db, self.name = db, name
        self.cache = BoundedCache(limit)
        db.execute(f'CREATE TABLE {name} (key TEXT PRIMARY KEY, value BLOB)')

    def __getitem__(self, key):
        if key not in self.cache:
            row = self.db.execute(f'SELECT value FROM {self.name} WHERE key=?', (key,)).fetchone()
            if row is None:
                raise KeyError(key)
            self.cache[key] = pickle.loads(zlib.decompress(row[0]))
        return self.cache[key]

    def __setitem__(self, key, value):
        payload = zlib.compress(pickle.dumps(value, protocol=5), 1)
        self.db.execute(f'INSERT OR REPLACE INTO {self.name} VALUES (?,?)', (key, payload))
        self.cache[key] = value

    def __contains__(self, key):
        return key in self.cache or self.db.execute(f'SELECT 1 FROM {self.name} WHERE key=?',(key,)).fetchone() is not None

    def __iter__(self):
        return (row[0] for row in self.db.execute(f'SELECT key FROM {self.name} ORDER BY key'))

    def __len__(self):
        return self.db.execute(f'SELECT count(*) FROM {self.name}').fetchone()[0]


class DiskPositionPairs:
    """Canonical exact distinct pairs for directional diagnostic unions."""
    def __init__(self, db, name, rows):
        self.db, self.name = db, name
        db.execute(f'CREATE TABLE {name} (a INTEGER, b INTEGER, PRIMARY KEY(a,b)) WITHOUT ROWID')
        for pos, mask in rows.items():
            while mask:
                bit = mask & -mask
                other = bit.bit_length() - 1
                a, b = sorted((pos, other))
                db.execute(f'INSERT OR IGNORE INTO {name} VALUES (?,?)', (a, b))
                mask ^= bit

    def __len__(self):
        return self.db.execute(f'SELECT count(*) FROM {self.name}').fetchone()[0]

    def __iter__(self):
        return iter(self.db.execute(f'SELECT a,b FROM {self.name} ORDER BY a,b'))


def schedule_pairs(db, pairs, limit):
    # The SQL ordering is exactly Python's (tier, weight, gap, (a,b)).
    packed = isinstance(pairs, DiskPairObjects)
    key_type, endpoint_type = ('INTEGER', 'INTEGER') if packed else ('TEXT', 'TEXT')
    db.execute(f'CREATE TABLE ranked (key {key_type} PRIMARY KEY, tier INTEGER, weight REAL, gap REAL, a {endpoint_type}, b {endpoint_type})')
    for pair,(rank,_) in pairs.items():
        endpoints = tuple(pairs.positions[i] for i in pair) if packed else pair
        db.execute('INSERT INTO ranked VALUES (?,?,?,?,?,?)',
            (pairs.encode(pair), *rank[:3], *endpoints))
    db.execute('CREATE TABLE scheduled AS SELECT key FROM ranked ORDER BY tier,weight,gap,a,b LIMIT ?', (limit,))
    db.execute('CREATE UNIQUE INDEX scheduled_key ON scheduled(key)')
    for (key,) in db.execute('SELECT key FROM scheduled ORDER BY key'):
        pair = pairs.decode(key) if packed else tuple(json.loads(key))
        yield pair,pairs[pair]


def json_array_records(handle, chunk_size=65536):
    """Incremental JSON array decoder; validates the entire document before ingress."""
    decoder = json.JSONDecoder()
    def scan():
        handle.seek(0)
        buffer, ended = '', False
        def fill():
            nonlocal buffer, ended
            text = handle.read(chunk_size)
            buffer += text
            ended = not text
        fill()
        if not buffer.startswith('['):
            raise ValueError('invalid_array')
        buffer = buffer[1:]
        expect_value, seen = True, False
        while True:
            buffer = buffer.lstrip()
            if not buffer and not ended:
                fill()
                continue
            if buffer.startswith(']'):
                if expect_value and seen:
                    raise ValueError('trailing_comma')
                buffer = buffer[1:]
                while not ended:
                    fill()
                if buffer.strip():
                    raise ValueError('trailing_content')
                return
            if not expect_value:
                if not buffer.startswith(','):
                    raise ValueError('missing_comma')
                buffer, expect_value = buffer[1:], True
                continue
            try:
                value, stop = decoder.raw_decode(buffer)
                # A number may end at the current chunk boundary.
                if not ended and (stop == len(buffer) or type(value) in (int,float) and buffer[stop] not in ',] \r\n\t'):
                    fill()
                    continue
            except ValueError:
                if ended:
                    raise
                fill()
                continue
            yield value
            buffer, expect_value, seen = buffer[stop:], False, True
    try:
        for _ in scan():
            pass
    except ValueError:
        yield 'invalid JSON array'
        return
    yield from scan()

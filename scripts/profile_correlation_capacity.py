"""Development-only allocation probe; no fox replay or label access."""
import itertools
import json
from pathlib import Path
import sys
import tracemalloc
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.services.datasets import load_dataset
from app.adapters.wazuh import WazuhAdapter
from app.entities.extraction import extract_entities
from app.correlation.index import AlertIndex
from app.correlation.edges import peak_memory_mb
from app.services.storage import atomic_json, file_digest

out = ROOT/'outputs/correlation_v4_capacity'
out.mkdir(exist_ok=True)
paths = ['backend/app/adapters/base.py', 'backend/app/services/analysis.py',
 'backend/app/correlation/index.py', 'backend/app/correlation/candidates.py',
 'backend/app/correlation/scoring.py', 'backend/app/chains/assembly.py',
 'backend/app/entities/extraction.py', 'backend/app/dedup/grouping.py',
 'backend/app/services/storage.py', 'backend/app/services/bounded_diagnostics.py']
atomic_json(out/'before_hashes.json', {p:file_digest(ROOT/p) for p in paths})
for p in paths:
    dest = out/'before'/p
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes((ROOT/p).read_bytes())
loaded = load_dataset(ROOT, scene_id='russellmitchell', config_version='v4')
setting = loaded.sources['ait_ads.russellmitchell.wazuh'][1] if 'ait_ads.russellmitchell.wazuh' in loaded.sources else next(s for k,s in loaded.sources.values() if k=='wazuh')
path = next(ROOT/r['path'] for r in loaded.inputs if r['source']=='wazuh')
with path.open(encoding='utf8') as f:
    records = list(itertools.islice((json.loads(line) for line in f if line.strip()), 1000))
tracemalloc.start()
adapter = WazuhAdapter(loaded.config, setting)
alerts = adapter.batch(records).alerts
rows = [dict(stage='adapter', traced_bytes=tracemalloc.get_traced_memory()[0], count=len(alerts))]
extracted = extract_entities(alerts, {setting.source_namespace:setting})
rows.append(dict(stage='entity_extraction_with_old_alerts_retained', traced_bytes=tracemalloc.get_traced_memory()[0]))
index = AlertIndex(extracted.alerts, (), extracted.entities)
rows.append(dict(stage='index_with_old_alerts_retained', traced_bytes=tracemalloc.get_traced_memory()[0]))
atomic_json(out/'allocation_probe.json', dict(rows=rows, peak_rss_mb=peak_memory_mb(),
 projected_bit_bytes_per_473k_posting=sum((i//8+28) for i in range(473000)),
 fox_input_bytes={p.name:p.stat().st_size for p in (ROOT/'data/ait_ads/fox/raw').glob('*.json')},
 scope='first 1000 development Wazuh records, not fox replay; projections are not measurements'))
print(json.dumps(rows))

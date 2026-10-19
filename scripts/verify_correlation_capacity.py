"""Full frozen-v4 replay, exact capacity observation; only dev and fox, no GT."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import sys
import threading
import time
from collections import Counter
import math
import duckdb
import traceback
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.path.insert(0,str(ROOT/'scripts'))
from app.services import analysis, bounded_diagnostics as diagnostics
from app.services.capacity import IMPLEMENTATION_VERSION
from app.services.datasets import load_dataset
from app.services.storage import SnapshotStore, atomic_json, file_digest
from app.correlation.edges import correlation_version
from verify_correlation_v4 import DevelopmentObserver
from finalize_correlation_v4 import implementation_hashes
from demo_support import truth_guard

OUT = ROOT/'outputs/correlation_v4_capacity'
BaseDiagnostics = diagnostics.BoundedDiagnostics


class DiskScores:
    def __init__(self,owner,population):
        self.owner,self.population,self.count,self.histogram = owner,population,0,Counter()
    def append(self,score):
        self.owner.score_stream.add((self.population,score))
        self.histogram[self.owner.bucket(score)] += 1
        self.count += 1
    def __len__(self):
        return self.count


class CapacityObserver(DevelopmentObserver):
    def __init__(self,*args):
        super().__init__(*args)
        self.score_stream = diagnostics.ColumnarStream(self.details/'capacity_scores','population VARCHAR, score DOUBLE')
        self.scores = {k:DiskScores(self,k) for k in ('all','accepted','rejected')}
    def close(self):
        if hasattr(self,'monitor'):
            self.monitor.stage='diagnostic_report_generation'
        self.score_stream.close()
        db = duckdb.connect(':memory:')
        db.execute("SET memory_limit='256MB'")
        db.execute('SET threads=1')
        reports = {}
        try:
            for population,values in self.scores.items():
                quantiles = {}
                for name,q in [('P50',.5),('P75',.75),('P90',.9),('P95',.95),('P99',.99),('MAX',1.)]:
                    if not values.count:
                        quantiles[name] = None
                        continue
                    p = (values.count-1)*q
                    lo = math.floor(p)
                    rows = db.execute('SELECT score FROM read_parquet(?) WHERE population=? ORDER BY score LIMIT 2 OFFSET ?',
                        [str(self.score_stream.directory/'*.parquet'),population,lo]).fetchall()
                    a,b = rows[0][0],rows[-1][0]
                    quantiles[name] = a+(b-a)*(p-lo)
                buckets = [self.bucket(s) for s in (0.,.1,.2,.3,.4,.5,.6,.65,.7,.8,.9,1.)]
                reports[population] = dict(count=values.count,quantiles=quantiles,
                    histogram={b:values.histogram[b] for b in buckets})
        finally:
            db.close()
        report = dict(population='one best valid member per candidate, best rejected if no valid member',
            score_distribution=reports,evidence_composition={k:dict(sorted(v.items())) for k,v in self.composition.items()},
            evidence_proxies={k:dict(sorted(v.items())) for k,v in self.proxies.items()},proxy_semantics='selected-candidate-v2',
            ground_truth_used=False,classification='observable evidence proxies, not pair precision/recall')
        atomic_json(self.details/'development_audit.json',report)
        self.write(dict(stage='development_audit',summary=report),essential=True)
        BaseDiagnostics.close(self)


def memory():
    class Status(ctypes.Structure):
        _fields_ = [('length',wintypes.DWORD),('load',wintypes.DWORD)] + [(k,ctypes.c_ulonglong) for k in
            ('total_phys','avail_phys','total_page','avail_page','total_virtual','avail_virtual','extended')]
    class Counters(ctypes.Structure):
        _fields_ = [('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)] + [(k,ctypes.c_size_t) for k in
            ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
             'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage','PrivateUsage')]
    status, counters = Status(),Counters()
    status.length, counters.cb = ctypes.sizeof(status),ctypes.sizeof(counters)
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GlobalMemoryStatusEx(ctypes.byref(status))
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL('psapi',use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):
        raise OSError(ctypes.get_last_error())
    return dict(rss_mb=counters.WorkingSetSize/2**20,peak_rss_mb=counters.PeakWorkingSetSize/2**20,
        private_commit_mb=counters.PrivateUsage/2**20,available_commit_mb=status.avail_page/2**20,
        available_physical_mb=status.avail_phys/2**20)


class Monitor:
    def __init__(self,destination):
        self.destination = destination
        self.stage,self.started,self.minimum,self.peak = 'raw_ingestion',time.perf_counter(),float('inf'),0
        self.abort,self.stop = False,threading.Event()
        self.events = []
        self.thread = threading.Thread(target=self.sample,daemon=True)
    def sample(self):
        with (self.destination/'resource_samples.jsonl').open('w',encoding='utf8') as handle:
            while not self.stop.is_set():
                row = dict(stage=self.stage,elapsed_seconds=time.perf_counter()-self.started,**memory())
                self.minimum = min(self.minimum,row['available_commit_mb'])
                self.peak = max(self.peak,row['peak_rss_mb'])
                if row['available_commit_mb'] < 512:
                    self.abort = True
                handle.write(json.dumps(row)+'\n')
                handle.flush()
                self.stop.wait(2)
    def check(self):
        if self.abort:
            raise MemoryError('host_available_commit_below_512_MiB')
    def progress(self,row):
        # A resource abort must still reach failure bookkeeping and receipts.
        if row.get('stage') != 'finished':
            self.check()
        self.events.append({**row,'reported_elapsed_seconds':row.get('elapsed_seconds'),
            'elapsed_seconds':time.perf_counter()-self.started,**memory()})
        print(json.dumps(row),flush=True)
    def wrap(self,module,name,stage):
        original = getattr(module,name)
        def call(*args,**kwargs):
            self.check()
            self.stage = stage
            start = time.perf_counter()
            self.events.append(dict(stage=stage,event='start',elapsed_seconds=start-self.started,**memory()))
            try:
                result = original(*args,**kwargs)
            except Exception:
                traceback.print_exc()
                raise
            self.events.append(dict(stage=stage,event='end',duration_seconds=time.perf_counter()-start,
                elapsed_seconds=time.perf_counter()-self.started,**memory()))
            return result
        setattr(module,name,call)
    def close(self):
        self.stop.set()
        self.thread.join(5)
        final=memory()
        self.peak=max(self.peak,final['peak_rss_mb'])
        self.minimum=min(self.minimum,final['available_commit_mb'])
        atomic_json(self.destination/'capacity_profile.json',dict(events=self.events,
            peak_rss_mb=self.peak,minimum_available_commit_mb=self.minimum,resource_abort=self.abort,
            guard_mib=512,guard_disabled=False,guard_threshold_changed=False))


def run(scene,destination):
    if scene not in {'russellmitchell','fox'}:
        raise ValueError('capacity_data_boundary')
    if scene == 'fox':
        from finalize_correlation_capacity import execution_hashes
        lock = json.loads((OUT/'VALIDATION_LOCK.json').read_text(encoding='utf8'))
        equivalence = json.loads((OUT/'RUSSELLMITCHELL_EQUIVALENCE.json').read_text(encoding='utf8'))
        regression = json.loads((OUT/'REGRESSION_RESULT.json').read_text(encoding='utf8'))
        if equivalence['status'] != 'PASS' or not regression['passed'] or lock['implementation'] != execution_hashes():
            raise ValueError('fox_requires_equivalence_regression_and_unchanged_execution')
    destination = OUT/destination
    if not destination.resolve().is_relative_to(OUT.resolve()):
        raise ValueError('capacity_output_boundary')
    destination.mkdir(parents=True,exist_ok=False)
    monitor = Monitor(destination)
    monitor.wrap(analysis,'deduplicate','dedupe')
    monitor.wrap(analysis,'extract_entities','entity_extraction')
    monitor.wrap(analysis,'run_correlation','correlation_setup')
    monitor.wrap(analysis,'run_reconstruction','reconstruction')
    import app.correlation.edges as edges
    import app.incidents.triage as triage
    monitor.wrap(analysis.MeasuredAdapter,'read_file','adapter_parsing_and_canonical_construction')
    monitor.wrap(edges.AlertIndex,'__init__','entity_indexes_and_frequency')
    monitor.wrap(triage,'triage_singletons','single_alert_triage')
    monitor.wrap(SnapshotStore,'write_records','domain_persistence')
    monitor.wrap(SnapshotStore,'write_metadata','snapshot_publication')
    monitor.wrap(edges,'generate_candidates','candidate_generation')
    original_progress = monitor.progress
    def progress(row):
        stages = {'candidates':'scoring','clustering':'chain_reconstruction','chain':'chain_reconstruction',
                  'entities_complete':'correlation_setup','dedupe_complete':'entity_extraction',
                  'input_complete':'dedupe'}
        if row['stage'] in stages:
            monitor.stage = stages[row['stage']]
        original_progress(row)
    diagnostics.BoundedDiagnostics = CapacityObserver
    CapacityObserver.monitor=monitor
    loaded = load_dataset(ROOT,scene_id=scene,config_version='v4')
    atomic_json(destination/'recipe.json',dict(algorithm_version=correlation_version(loaded.config),
        execution_implementation=IMPLEMENTATION_VERSION,config_snapshot=loaded.config.snapshot,
        mapping_digest=loaded.config.mapping_digest,inputs=loaded.inputs,ground_truth_used=False))
    monitor.thread.start()
    try:
        with truth_guard(ROOT):
            service = analysis.AnalysisService(ROOT,configs={'v4':loaded.config},sources=loaded.sources,
                allowed_files=[v['path'] for v in loaded.inputs],execution_mode='bounded',
                resource_check=monitor.check,progress=progress)
            try:
                identity = service.create(loaded.request,background=False)
            finally:
                service.close()
            store = SnapshotStore(ROOT,identity)
            receipt = json.loads((store.domain/'run.json').read_text(encoding='utf8'))
            atomic_json(destination/'RUN.json',receipt)
            result = dict(analysis_id=identity,scene=scene,status=receipt['status'],is_complete=receipt['is_complete'],
                algorithm_version=correlation_version(loaded.config),execution_implementation=IMPLEMENTATION_VERSION,
                config_hash=receipt['config_hash'],mapping_digest=receipt['mapping_digest'],dataset_digest=receipt['dataset_digest'],
                counts=receipt['counts'],runtime=receipt['runtime'],peak_memory_mb=memory()['peak_rss_mb'],
                grounding=receipt.get('grounding'),errors=receipt['errors'],ground_truth_used=False,ai_used=False)
            if receipt['is_complete']:
                _,_,manifest = store.read_metadata()
                result['snapshot_identity'] = manifest['execution']['snapshot_identity']
            atomic_json(destination/'RESULT.json',result)
            print(json.dumps(result),flush=True)
    finally:
        monitor.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--scene',choices=['russellmitchell','fox'],required=True)
    parser.add_argument('--destination',required=True)
    args = parser.parse_args()
    run(args.scene,args.destination)

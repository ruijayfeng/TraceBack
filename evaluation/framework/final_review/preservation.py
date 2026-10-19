"""Recover exact archived historical bytes and isolate known legacy test writers."""
import shutil
import os
import datetime
import sys
from pathlib import Path
from .run import ROOT, OUT, read, save, sha


def restore():
    original=ROOT/'outputs/v5_formula_repair_integration'
    before=read(original/'before.json')['protected_files']
    restoration=read(original/'historical_restoration.json')
    actions=[]
    for row in restoration['files']:
        name=row['path'];source=original/'history_recovery'/name.split('/')[-1]
        expected=before[name]
        if sha(source)!=expected or row['restored_sha256']!=expected:
            raise ValueError('historical_backup_hash_not_proven:'+name)
        target=ROOT/name;attempt=OUT/'legacy_write_attempt'/target.name
        attempt.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(target,attempt)
        actual=sha(target)
        shutil.copyfile(source,target)
        if sha(target)!=expected:raise ValueError('historical_restore_failed:'+name)
        actions.append(dict(file=name,attempt_sha256=actual,restored_sha256=sha(target),
            expected_historical_sha256=expected,source=str(source.relative_to(ROOT)),
            archived_attempt=str(attempt.relative_to(OUT)),byte_match=True))
    save(OUT/'historical_write_restoration.json',dict(status='RESTORED_TO_VERIFIED_ARCHIVED_HASHES',
        explanation='Existing capacity regression test writes fixed historical OUT paths. Unisolated full attempts rewrote six equivalence files. Current attempts archived before recovery. No algorithm or test assertion changed.',
        original_pre_review_hashes_for_these_six_were_not_captured=True,
        provenance='Independent preexisting formula_repair before.json + historical_restoration.json + history_recovery bytes all agree; recovery uses those exact archived hashes, not regenerated current PASS evidence.',
        verification_artifacts={str(p.relative_to(ROOT)):sha(p) for p in [original/'before.json',original/'historical_restoration.json']},files=actions))
    print('HISTORICAL_BYTES_RESTORED',len(actions),flush=True)


def audit_mtimes():
    start=datetime.datetime.fromisoformat(read(OUT/'run_manifest.json')['created_at']).timestamp()
    recent=[];count=0
    for directory,dirs,files in os.walk(ROOT/'outputs'):
        for name in files:
            p=Path(directory)/name;s=p.stat();count+=1
            if s.st_mtime>=start:recent.append(dict(file=p.relative_to(ROOT).as_posix(),bytes=s.st_size,mtime=s.st_mtime))
    save(OUT/'historical_output_mtime_audit.json',dict(files_scanned=count,recent_files=recent,
        limitation='mtime is a discovery aid, not a pre-review content seal or proof against restored timestamps'))
    print('HISTORICAL_MTIME_SCAN',count,len(recent),[x['file'] for x in recent[:30]],flush=True)


if __name__=='__main__':
    audit_mtimes() if 'audit' in sys.argv else restore()

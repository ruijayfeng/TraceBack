"""Explicit development configuration and historical *artifact* verification.

Historical loaders remain strict: none of these functions makes current source
bytes pass a historical implementation freeze. Archived hash inventories attest
past implementation identity; they are not claimed to be executable archives.
"""
from pathlib import Path
import json

from . import ROOT, OUT, IDENTITY, VERSION, PREVIOUS
from evaluation.framework.v4_semisynthetic_baseline.common import read, sha


def verify_provenance_anchors():
    path = OUT / 'provenance_seal.json'
    if not path.exists(): return
    sealed = read(path)
    for key, name in (('freeze_receipt','freeze_receipt.json'),
                      ('integration_before','integration_before.json'),
                      ('historical_additional','historical_additional.json')):
        if sha(OUT / name) != sealed[key]:
            raise ValueError('integration_provenance_anchor_changed:' + name)


def development_config():
    from app.services.storage import restore_config
    snapshot = read(PREVIOUS / 'preparation.json')['algorithm']
    snapshot['implementation_version'] = IDENTITY
    config = restore_config(snapshot)
    return config, {'baseline_name': 'V5_PRE_FORMULA_BASELINE',
                    'algorithm_version': VERSION, 'algorithm_snapshot': config.snapshot,
                    'mapping_digest': config.mapping_digest, 'threshold': .65}, OUT / 'freeze_receipt.json'


def development_cptc():
    from app.adapters.base import AdapterSettings
    saved = read(ROOT / 'outputs/cptc_2018_step3a_t5/recipe.json')
    config, _, _ = development_config()
    return config, {k: AdapterSettings(**v) for k, v in saved['config_snapshot']['sources'].items()}, saved


def verify_historical_inventory(expected, *, anchor=None):
    """Check immutable historical inventory against its pre-edit seal.

    Files in outputs/data are checked byte-for-byte now. Historical source and
    config entries are checked against the sealed historical inventory, never
    against current source, and are explicitly reported as identity attestations.
    """
    verify_provenance_anchors()
    before = read(OUT / 'integration_before.json')
    identity, artifacts = {}, {}
    if anchor is not None:
        anchor = Path(anchor)
        rel = anchor.relative_to(ROOT).as_posix()
        if sha(anchor) != before['historical_files'][rel]:
            raise ValueError('historical_inventory_changed:' + rel)
        value = read(anchor)
        if value != expected:
            raise ValueError('historical_inventory_content_mismatch:' + rel)
    known = before['historical_identities']
    for path, digest in expected.items():
        if path.startswith(('outputs/', 'data/')):
            if sha(ROOT / path) != digest:
                raise ValueError('historical_artifact_changed:' + path)
            artifacts[path] = digest
        else:
            if digest not in known.get(path, []):
                raise ValueError('unattested_historical_identity:' + path)
            identity[path] = digest
    return {'status': 'PASS', 'artifact_bytes_verified': len(artifacts),
            'historical_source_identity_attestations': len(identity),
            'historical_source_reexecution_verified': False}


def verify_current():
    verify_provenance_anchors()
    receipt = read(OUT / 'freeze_receipt.json')
    if receipt.get('baseline_name') == 'V5_PRE_FORMULA_BASELINE':
        current_files = {p.relative_to(ROOT).as_posix() for p in (ROOT/'backend/app').rglob('*')
                         if p.is_file() and '__pycache__' not in p.parts}
        if current_files != set(receipt['implementation_file_hashes']):
            raise ValueError('current_preformula_baseline_file_set_changed')
        configs = {p.relative_to(ROOT).as_posix() for p in (ROOT/'configs').rglob('*.yaml')}
        recorded = {p for p in receipt['configuration_file_hashes'] if p.startswith('configs/')}
        if configs != recorded:
            raise ValueError('current_preformula_configuration_file_set_changed')
    for key in ('implementation_file_hashes', 'configuration_file_hashes', 'mapping_hashes'):
        for p, h in receipt[key].items():
            if sha(ROOT / p) != h:
                raise ValueError('current_preformula_baseline_changed:' + p)
    return receipt

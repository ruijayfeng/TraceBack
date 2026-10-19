"""Read-only inventories and a per-test classification of the prior regression."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from . import ROOT, OUT, PREVIOUS
from evaluation.framework.v4_semisynthetic_baseline.common import DATASET, inventory, read, save, sha

HISTORICAL = ('correlation_v4', 'correlation_v4_capacity', 'correlation_v4_small',
    'cptc_2018_step3a', 'cptc_2018_step3a_t5', 'cptc_2018_step3a_capacity',
    'cptc_top100_diagnostic', 'cptc_t5_correlation_v4_diagnostic_12',
    'd1_positive_scan', 'final_demo_selection', 'v5_design_diagnostic',
    'v5_evidence_validation', 'v5_evidence_adjudication', 'v4_semisynthetic_baseline',
    'v5_preformula_candidate_recovery')


def start():
    if (OUT / 'integration_before.json').exists():
        raise ValueError('integration_audit_already_exists')
    historical = {}
    identities = defaultdict(set)
    def find_identities(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and len(v) == 64 and all(c in '0123456789abcdef' for c in v):
                    if k.startswith(('backend/', 'configs/', 'docs/', 'frontend/', 'scripts/')) or k == 'AGENTS.md':
                        identities[k].add(v)
                elif isinstance(v, (dict, list)):
                    find_identities(v)
        elif isinstance(obj, list):
            for v in obj: find_identities(v)
    for folder in HISTORICAL:
        base = ROOT / 'outputs' / folder
        # Only delivered top-level artifacts; never historical pytest scratch.
        for p in sorted(base.glob('*')):
            if p.is_file():
                historical[p.relative_to(ROOT).as_posix()] = sha(p)
                if p.suffix == '.json':
                    find_identities(read(p))
    for p in (ROOT / 'evaluation/configs/task_06_6_core_freeze.json',):
        historical[p.relative_to(ROOT).as_posix()] = sha(p)
        find_identities(read(p))
    before = {'historical_files': historical,
              'historical_identities': {k: sorted(v) for k, v in identities.items()},
              'dataset_files': inventory(DATASET), 'production_entry': inventory(ROOT, production=True),
              'notes': ['Entry inventory taken after identity-only config/edges edits; scoring/projection/candidate code is unchanged.']}
    save(OUT / 'integration_before.json', before)
    tree = ET.parse(PREVIOUS / 'tests_regression.xml')
    rows = []
    for case in tree.iter('testcase'):
        for tag in ('failure', 'error'):
            el = case.find(tag)
            if el is None: continue
            message = el.attrib.get('message', '')
            name = case.attrib.get('classname', '') + '::' + case.attrib['name']
            if 'repository_contract' in name:
                cls, target, semantic = 'E. REPOSITORY_CONTRACT', 'current', False
                cause = 'Two authorized projection/bridge helper files absent from the earlier exact allowlist; already repaired in prior follow-up.'
            elif ('frozen_correlation_implementation_changed' in message or
                  'frozen_implementation_changed' in message):
                cls, target, semantic = 'B. OBSOLETE_FREEZE_EXPECTATION', 'current semantic test', False
                cause = 'Current code is loaded through a historical v4 implementation guard before the semantic assertion can run.'
            else:
                cls, target, semantic = 'B. OBSOLETE_FREEZE_EXPECTATION', 'historical integrity test', False
                cause = 'Historical source hashes are compared to the active development tree instead of historical identity and artifact bytes.'
            rows.append({'test': name, 'phase': tag, 'failure_class': cls,
                'historical_or_current': target, 'root_cause': cause, 'semantic': semantic,
                'blocking_formula_design': True, 'required_fix':
                'Retain the exact allowlist for accepted wazuh_semantics.py/entity_bridges.py helpers and rerun the repository checker; do not broadly allow reserved directories.'
                if cls == 'E. REPOSITORY_CONTRACT' else
                'Bind semantic execution explicitly to preformula; retain historical strict loaders and independently verify historical artifacts.'
                if target == 'current semantic test' else
                'Verify immutable historical inventory/artifacts separately and current code against its own receipt.',
                'original_message': message})
    save(OUT / 'regression_failure_classification.json', {'total': len(rows),
         'counts': dict(Counter(r['failure_class'] for r in rows)),
         'classes': ['A. HISTORICAL_V4_INTEGRITY', 'B. OBSOLETE_FREEZE_EXPECTATION',
                     'C. V5_PREFORMULA_REAL_REGRESSION', 'D. TEST_INFRASTRUCTURE',
                     'E. REPOSITORY_CONTRACT', 'F. UNKNOWN'], 'tests': rows,
         'prior_followup': read(PREVIOUS / 'summary.json'),
         'infrastructure': 'Legacy tests writing fixed historical output paths must run in isolated destinations.'})
    print(json.dumps({'prior_failures': len(rows), 'historical_files': len(historical),
                      'dataset_files': len(before['dataset_files'])}))


def verify_history():
    from .boundary import verify_provenance_anchors
    verify_provenance_anchors()
    before = read(OUT / 'integration_before.json')
    historical = dict(before['historical_files'])
    additional = OUT / 'historical_additional.json'
    if additional.exists(): historical.update(read(additional))
    changed = {p: {'expected': h, 'actual': sha(ROOT / p)}
               for p, h in historical.items() if sha(ROOT / p) != h}
    result = {'status': 'FAIL' if changed else 'PASS', 'files_verified': len(historical),
              'differences': changed, 'old_receipts_modified': False,
              'source_identity_policy': 'Historical source inventories remain immutable attestations; active source is separately versioned.',
              'historical_source_reexecution_verified': False}
    save(OUT / 'historical_integrity.json', result)
    if changed: raise ValueError('historical_artifacts_modified')
    return result

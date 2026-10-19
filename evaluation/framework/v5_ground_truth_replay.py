"""Truth-first investigation and honest no-witness stop for frozen V4.

No scoring is run without an independently accepted witness. Prior candidate
labels/scores are not used to search or manufacture true edges.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

from evaluation.framework.v5_truth_acquisition import ROOT, OUT, TRUTH, records, save, sha

PRIOR = ROOT / 'outputs/v5_evidence_adjudication'
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'backend'))


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def freeze():
    import v5_design_diagnostic as d
    config, _, _ = d.load_frozen_config()
    expected = read(PRIOR / 'freeze_verification.json')
    current = dict(algorithm_version=d.correlation_version(config), config_hash=config.config_hash,
        mapping_digest=config.mapping_digest, threshold=config.algorithm.score.correlation_threshold,
        candidate_recipe=config.algorithm.candidate.model_dump(mode='json'))
    mismatches = []
    for k, v in current.items():
        if v != expected[k]:
            mismatches.append(dict(field=k, expected=expected[k], actual=v))
    protected = read(PRIOR / 'protected_before.json')
    for directory in ('v5_evidence_adjudication', 'v5_evidence_validation', 'v5_design_diagnostic'):
        folder = ROOT / 'outputs' / directory
        manifest = read(folder / 'manifest.json')
        for name, digest in manifest['files'].items():
            protected[(folder / name).relative_to(ROOT).as_posix()] = digest
        protected.update(manifest.get('source_hashes', {}))
        protected[(folder / 'manifest.json').relative_to(ROOT).as_posix()] = sha(folder / 'manifest.json')
    for name, digest in sorted(protected.items()):
        p = ROOT / name
        actual = sha(p) if p.is_file() else None
        if actual != digest:
            mismatches.append(dict(path=name, expected=digest, actual=actual))
    # Include all current production/config/frontend bytes, independent of Git.
    for base in ('backend/app', 'configs', 'frontend/src', 'docs'):
        for p in sorted((ROOT / base).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                protected.setdefault(p.relative_to(ROOT).as_posix(), sha(p))
    before_path = OUT / 'protected_before.json'
    if before_path.exists():
        before = read(before_path)
        for name in sorted(set(before) | set(protected)):
            if before.get(name) != protected.get(name):
                mismatches.append(dict(path=name, error='task-entry inventory changed'))
    else:
        save(before_path, protected)
    result = dict(**current, status='FAIL' if mismatches else 'PASS', mismatches=mismatches,
        protected_file_count=len(protected), git_status='UNAVAILABLE_NO_GIT_METADATA',
        previous_report_sha256=sha(PRIOR / 'V5_EVIDENCE_ADJUDICATION_REPORT.md'),
        previous_manifest_sha256=sha(PRIOR / 'manifest.json'),
        source_capability_attestation_sha256=sha(PRIOR / 'source_capability_attestation.json'),
        production_v4_modified='NO' if not mismatches else 'UNKNOWN', production_v5_implemented='NO')
    save(OUT / 'freeze_verification.json', result)
    if mismatches:
        raise RuntimeError('frozen bytes/recipe mismatch; see freeze_verification.json')
    return result


def investigate():
    sources = read(OUT / 'ground_truth_sources.json')
    inventory = []
    for source in sources['sources']:
        if source['status'] != 'ACQUIRED' or not source['path'].endswith('.gz'):
            continue
        p = ROOT / source['path']
        if sha(p) != source['sha256']:
            raise ValueError('acquired evidence changed: ' + str(p))
        hosts, log_sources, tables, times = Counter(), Counter(), Counter(), Counter()
        samples, signals = defaultdict(list), Counter()
        total = 0
        for ordinal, row in records(p):
            total += 1
            host, raw = row.get('host'), row.get('_raw', '')
            hosts[host] += 1
            log_sources[row.get('source')] += 1
            times[(host, row.get('_time'))] += 1
            kinds = []
            for kind, pattern in [('ssh_accepted', r'sshd\[\d+\]: Accepted '),
                ('command_equals_text', r'COMMAND='), ('session_opened', r'session opened'),
                ('attack_tool_or_sensitive_command', r'(?:/etc/shadow|msfconsole|meterpreter|nc -.*-e |/dev/tcp|sqlmap|hydra )'),
                ('database_statement', r'STATEMENT:'), ('database_error', r'ERROR:'),
                ('web_execution_error', r'(?:eval\(\)|PHP.*(?:Fatal|Warning)|Permission denied)')]:
                if re.search(pattern, raw, re.I):
                    signals[kind] += 1
                    kinds.append(kind)
            if p.name.startswith('osqueryd_results'):
                obj = json.loads(raw)
                tables[obj.get('name')] += 1
                if obj.get('name') == 'shell_history':
                    signals['shell_history_rows'] += 1
                    if not obj.get('columns', {}).get('time'):
                        signals['shell_history_missing_execution_timestamp'] += 1
            if p.name == 'term.json.gz':
                signals['apt_terminal_rows' if '/apt/' in str(row.get('source')) else 'other_terminal_rows'] += 1
            for kind in kinds:
                if len(samples[kind]) < 4:
                    samples[kind].append(dict(export_line=ordinal, export_cd=row.get('_cd'),
                        timestamp=row.get('_time'), host=host, source=row.get('source'),
                        raw=raw, raw_sha256=__import__('hashlib').sha256(raw.encode()).hexdigest()))
        inventory.append(dict(path=source['path'], sha256=source['sha256'], records=total,
            hosts=dict(sorted(hosts.items())), log_sources=dict(sorted(log_sources.items())),
            osquery_tables=dict(sorted(tables.items())), signals=dict(signals),
            max_rows_sharing_host_and_export_timestamp=max(times.values(), default=0),
            samples=dict(samples)))
    save(TRUTH / 'evidence_inventory.json', inventory)
    return inventory


def projection():
    from app.models import CanonicalAlert
    import v5_evidence_adjudication_evidence as evidence
    families = ('ACCOUNT', 'SESSION', 'FLOW_ID', 'HTTP', 'URL', 'ENDPOINT_ROLE', 'ATTACK_SEMANTIC', 'PROCESS')
    counts = {f:Counter() for f in families}
    samples = {f:[] for f in families}
    cache = PRIOR / 'cache/cptc_t5_dev_10k.jsonl'
    n = 0
    for line in cache.open(encoding='utf8'):
        row = json.loads(line)
        alert = CanonicalAlert.model_validate(row['alert'])
        observed = evidence.observations(alert)
        n += 1
        for family in families:
            if family not in observed:
                continue
            fact = observed[family]
            counts[family]['raw_observable'] += 1
            # HTTP is structured raw-only; URL retention does not retain the bundle.
            canonical = fact.get('canonical_field') is not None and family not in {'HTTP', 'FLOW_ID', 'ATTACK_SEMANTIC'}
            counts[family]['canonical_retained' if canonical else 'raw_only_evidence'] += 1
            if len(samples[family]) < 3:
                samples[family].append(dict(alert_id=alert.alert_id, locator=row['locator'],
                    raw_pointer=fact['pointer'], canonical_field=fact.get('canonical_field'),
                    canonical_retained=canonical, qualification=fact['qualification']))
    result = dict(scope='frozen CPTC 10k slice; diagnostic projection presence, not truth step observability',
        alert_count=n, cache_sha256=sha(cache), adapter_modified=False,
        semantics='Retained means an explicit canonical field/role preserves the observed family. Request attack tags are diagnostic only; mapped category is detector semantics, not execution/outcome.',
        families={f:dict(**dict(counts[f]), projection_retention_rate=(counts[f]['canonical_retained']/counts[f]['raw_observable'] if counts[f]['raw_observable'] else None),
            metric_status='available' if counts[f]['raw_observable'] else 'not_applicable', evidence=samples[f]) for f in families})
    save(OUT / 'projection_gap_analysis.json', result)
    return result


def write_insufficient(inventory, projection_result):
    reason = ('No independently grounded >=3-step attack progression with two causally supported consecutive edges was established. '
        'SSH authentication outcomes exist, but host/user/time continuity and batch-written shell histories do not prove session-to-command lineage. '
        'term is apt package installation; osquery has shell-history snapshots but no process-execution lineage tables in inspected T5 exports. '
        'Database statements include logged failures; statements alone do not prove successful exploitation. '
        'This is bounded acquisition, not proof that the full CPTC collection lacks truth.')
    save(OUT / 'truth_progressions.json', dict(status='INSUFFICIENT', progressions=[],
        strength_counts=dict(STRONG=0, MEDIUM=0, WEAK=0), reason=reason))
    for name in ('truth_alert_mapping.jsonl', 'blind_replay_results.jsonl', 'true_edge_reachability.jsonl'):
        (OUT / name).write_text('', encoding='utf8')
    for name in ('candidate_recall.json', 'admission_recall.json'):
        save(OUT / name, dict(numerator=0, denominator=0, value=None,
            metric_status='not_applicable', reason='zero verified observable true edges; replay not executed'))
    save(OUT / 'source_observability.json', dict(truth_nodes=0, observable_truth_nodes=0,
        truth_edges=0, observable_truth_edges=0, source_observability_ceiling=None,
        metric_status='not_applicable', reason='No accepted independent witness; unavailable denominator is not a source failure.',
        mapping_status_counts={k:0 for k in ('DIRECT_MATCH','MULTI_ALERT_MATCH','PARTIAL_MATCH','NOT_OBSERVABLE')}))
    save(OUT / 'progression_reconstruction.json', dict(counts={k:0 for k in
        ('FULL','PARTIAL','CANDIDATE_ONLY','BROKEN_AT_CANDIDATE','SOURCE_LIMITED')},
        metric_status='not_applicable', reason='No accepted witness. No SSH lifecycle relabeled as multi-stage attack.'))
    save(OUT / 'failure_taxonomy.json', dict(counts={k:0 for k in
        ('SOURCE_NOT_OBSERVABLE','CANONICAL_PROJECTION_LOSS','CANDIDATE_MISS','EVIDENCE_GATE','SCORE_BELOW_THRESHOLD','ADMITTED')},
        primary_failure_point=None, investigation_blocker='GROUND_TRUTH_INSUFFICIENT',
        reason='Algorithm failure location cannot be established without truth. Diagnostic projection gaps do not establish a lost true edge.'))
    save(OUT / 'truth_leakage_verification.json', dict(
        GROUND_TRUTH_USED_FOR_NOMINATION='NO', GROUND_TRUTH_USED_FOR_SCORING='NO',
        GROUND_TRUTH_USED_FOR_FEATURES='NO', GROUND_TRUTH_USED_FOR_POST_HOC_VALIDATION='YES',
        post_hoc_validation_status='TRUTH_QUALIFICATION_ONLY_NO_PREDICTION_COMPARISON',
        blind_replay_status='NOT_RUN_GROUND_TRUTH_INSUFFICIENT',
        runtime_real_replay_guard_verification='NOT_APPLICABLE_NO_REPLAY',
        automated_guard_tests_ref='test_results.xml',
        limitation='Python audit tripwire is not an OS sandbox; new worker must not inherit truth objects/descriptors.'))
    save(OUT / 'summary.json', dict(task_result='V5_REPLAY_GROUND_TRUTH_INSUFFICIENT',
        V5_FORMULA_DESIGN_GATE='NOT_READY', real_progressions=0, replay_completed=False,
        acquired_truth_records=sum(x['records'] for x in inventory), reason=reason))
    acquired = read(OUT / 'ground_truth_sources.json')['sources']
    report = f'''# V5 Ground-Truth Progression Witness Acquisition & Blind Replay

TASK_RESULT=V5_REPLAY_GROUND_TRUTH_INSUFFICIENT
V5_FORMULA_DESIGN_GATE=NOT_READY

## Result and eight required answers

1. Independently grounded real progressions: **0** (STRONG 0 / MEDIUM 0 / WEAK 0 accepted). Independent evidence acquired is not automatically a progression.
2. Observable attack steps among accepted progressions: **0**; observability ceiling **null / not_applicable**.
3. Observable true edges: **0**.
4. Candidate Recall: **null / not_applicable**, denominator 0.
5. Admission Recall: **null / not_applicable**, denominator 0. Frozen threshold remains **0.65**.
6. FULL / PARTIAL / CANDIDATE_ONLY / BROKEN_AT_CANDIDATE / SOURCE_LIMITED: **0 each**; no eligible progression.
7. Algorithm failure point: **not established**. Investigation blocker: **GROUND_TRUTH_INSUFFICIENT**. Existing projection gaps are separately measured; they do not prove a missed real edge.
8. Evidence sufficient for V5_FORMULA_DESIGN: **NO / NOT_READY**.

## Acquisition and source independence

RIT's [CPTC mirror](https://mirrors.rit.edu/cptc/cptc3/) lists the same six partition names as local CPTC-2018.
The [T5 events index](https://mirrors.rit.edu/cptc/cptc3/t5/events/) exposes endpoint/server/authentication evidence in addition to alerts.
Acquired {sum(s['status']=='ACQUIRED' for s in acquired)} of {len(acquired)} requested resources; parsed {len(inventory)} compressed evidence exports and {sum(x['records'] for x in inventory):,} truth-domain records.
These are independent record types, not an independent human panel or verified campaign labels. Remote/local export correspondence must be verified event by event before any truth-to-alert mapping; equal partition names are not proof.

Source-first selection covered bash history, apt terminal, SSH/PAM authentication, Apache error and access exports for all six existing teams. T5 endpoint osquery and application/database diagnostics were inspected in greater depth. Selection never used prior candidate scores, admitted flags, attacker-IP filtering, or the 94 review labels. Full gzip SHA-256, original URL, source paths, host names, counts and content-bound excerpts are retained in ground_truth_sources.json and truth_domain/evidence_inventory.json. An export line plus Splunk _cd identifies samples; neither is used as a production Stable ID.

{reason}

No three-event authentication lifecycle or ordered scanner requests were promoted into an attack progression. Same user/host, batch export time and a successful SSH authentication are insufficient to bind later shell commands to that exact attack session. No fabricated weak witnesses, negative labels or alert mappings were added.

## Scope and remaining evidence

This bounded investigation did not acquire VM images, T5 ps (~214 MB compressed), lsof (~98 MB), Windows event logs, all network streams or the full six-team osquery corpus. These are documented additional evidence leads, not evidence of absence. The public mirror exposes stronger telemetry, so replacement of the entire dataset is not yet justified. Next acquisition should obtain timestamped shell transcripts/process ancestry and an organizer/team report that binds a successful entry to subsequent commands and outcomes; then map exact actions into source alerts. Bash command timestamps require validation because multiple commands share flush-time timestamps; T5 osquery shell_history explicitly has an empty execution-time column.

No truth-driven alert slice was selected because no witness qualified. No 331,554-alert canonicalization, pair enumeration, score replay or tuning occurred. The existing 10,000-alert CPTC slice was used only for diagnostic projection accounting, with normal background preserved. Blind replay is **NOT RUN**; the empty replay/reachability JSONL files mean no eligible input, not a successful empty replay.

## Projection diagnostic

projection_gap_analysis.json recomputes ACCOUNT / SESSION / FLOW_ID / HTTP / URL / ENDPOINT_ROLE / ATTACK_SEMANTIC / PROCESS observations over {projection_result['alert_count']:,} immutable cached CanonicalAlerts. Raw-only evidence is distinguished from canonical retention; HTTP bundle retention is not inferred from URL retention, and a diagnostic request tag is not successful execution evidence. Missing observations have null retention rates. These counts do not enter recall denominators. Production adapters were not changed.

## Freeze, isolation and reproducibility

freeze_verification.json verifies the historical report/manifest/capability attestation, exact algorithm/config/mapping/threshold/candidate recipe and historical protected bytes. It also protects production, configs, frontend and seven baseline documents before/after this stage. No Git metadata exists, so SHA-256 receipts are used.

GROUND_TRUTH_USED_FOR_NOMINATION=NO
GROUND_TRUTH_USED_FOR_SCORING=NO
GROUND_TRUTH_USED_FOR_FEATURES=NO
GROUND_TRUTH_USED_FOR_POST_HOC_VALIDATION=YES (truth qualification only; no prediction comparison)

All truth readers live under evaluation/framework. Raw logs remain exclusively under this output's truth_domain, never data/input/alerts, raw_alert, AI prompts or production caches. The new allowlisted Python TruthGuard rejects truth-file reads, non-allowlisted data, child processes and explicit truth keys in input dictionaries; automatic fault-injection tests exercise these boundaries. Its real replay execution is not claimed because no replay ran. It is a trusted-Python audit tripwire, not an OS-level sandbox.

Reproduce diagnostic/report generation: `.venv/Scripts/python.exe -m evaluation.framework.v5_ground_truth_replay`. Evidence acquisition: `.venv/Scripts/python.exe -m evaluation.framework.v5_truth_acquisition --acquire` (network availability may change; immutable acquired bytes are the run's evidence). Tests: test_results.xml and TEST_RESULTS.md. No production V5 was implemented; no formula, weight, nomination, budget, clustering or reconstruction changes were made.

Targeted guard/isolation tests: **33 passed**. Affected regression suite: **272 passed, 1 failed**. The failure is an older Task 06.6 freeze-receipt check; all 18 flagged files match this task-entry inventory (regression_failure_classification.json). The historical receipt was not changed; the broader suite is not fully green.
'''
    (OUT / 'V5_GROUND_TRUTH_REPLAY_REPORT.md').write_text(report, encoding='utf8')


def manifest():
    save(OUT / 'manifest.json', dict(version='v5-ground-truth-acquisition-1',
        task_result='V5_REPLAY_GROUND_TRUTH_INSUFFICIENT', V5_FORMULA_DESIGN_GATE='NOT_READY',
        files={p.relative_to(OUT).as_posix():sha(p) for p in sorted(OUT.rglob('*'))
               if p.is_file() and p.name != 'manifest.json' and 'pytest_tmp' not in p.parts},
        source_hashes={p.relative_to(ROOT).as_posix():sha(p) for p in
            [Path(__file__), ROOT/'evaluation/framework/v5_truth_acquisition.py',
             ROOT/'evaluation/framework/v5_truth_guard.py', ROOT/'evaluation/tests/test_v5_ground_truth_replay.py']
            if p.exists()}))


def main():
    freeze()
    inventory = investigate()
    proj = projection()
    write_insufficient(inventory, proj)
    freeze()
    manifest()
    print(json.dumps(read(OUT / 'summary.json')))


if __name__ == '__main__':
    main()

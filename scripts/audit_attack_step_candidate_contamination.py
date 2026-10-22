"""AUDIT_ONLY. Inspect sealed v1 data and source; never import or execute v1.

GT is joined after native evidence interpretation. Counterfactuals are set
subtractions on the frozen ledger, not modified grouping runs or new gates.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import unicodedata

EXPECTED_SHA = '21405c45e5be606ee381fc45fd9e2fbd315fb1cbcf7254f15826805bfcaa0cba'
DEFAULT_OUTPUT = 'outputs/attack_step_candidate_contamination_audit_20261022'
CATEGORIES = ('SAME_STEP_EVIDENCE', 'CROSS_STEP_RELATION', 'SHARED_CONTEXT_ONLY',
              'SEMANTIC_SIMILARITY_ONLY', 'AMBIGUOUS')
TRUTH = ('EXACT_GT_STEP', 'PURE_GT_SUBSET', 'CROSS_GT_MIXED')
ROOTS = dict(
    A='A_ACCEPTED_RELATION_OVER_ADMISSION', B='B_PROCESS_LINEAGE_OVER_ADMISSION',
    C='C_SESSION_CONTEXT_OVER_ADMISSION', D='D_FLOW_CONTEXT_OVER_ADMISSION',
    E='E_HOST_ACCOUNT_CONTEXT_OVER_ADMISSION', F='F_SEMANTIC_LABEL_OVER_ADMISSION',
    G='G_CROSS_ACTION_ASSOCIATION_MISINTERPRETED', H='H_GROUP_EXPANSION_CONTAMINATION',
    I='I_RETENTION_GATE_TOO_WEAK', J='J_ENUMERATION_ARTIFACT',
    K='K_INSUFFICIENT_STEP_BOUNDARY_MODEL', L='L_OTHER')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def lines(path):
    return [json.loads(x) for x in Path(path).read_text(encoding='utf-8-sig').splitlines() if x.strip()]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def pointer(value, path):
    """RFC6901 including empty root; source models normalize Unicode keys."""
    if not path:
        return value
    if not path.startswith('/'):
        raise ValueError('Not an RFC6901 pointer')
    for token in path[1:].split('/'):
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            value = value[int(token)]
        else:
            if token not in value:
                token = next(k for k in value if unicodedata.normalize('NFC', k) == token)
            value = value[token]
    return value


def loc(root, filename, needle):
    path = root / 'backend/app/attack_steps' / filename
    source = path.read_text(encoding='utf-8')
    ast.parse(source)  # Syntax inspection only; no exec/import.
    matches = [i for i, line in enumerate(source.splitlines(), 1) if needle in line]
    if len(matches) != 1:
        raise ValueError(f'Ambiguous source anchor: {filename}:{needle}')
    return str(path.resolve()) + ':' + str(matches[0])


def source_locations(root):
    anchors = {
        'pair': ('candidate.py', "for a,b in combinations(ids,2):"),
        'singleton': ('candidate.py', "for sid in ids: add"),
        'relation': ('candidate.py', "add([d['stage_a_id']"),
        'context_bucket': ('candidate.py', "if len(c['stage_ids'])>1:"),
        'binding_bucket': ('candidate.py', "add(members,'EXISTING_'+field.upper()"),
        'explicit_request': ('candidate.py', "if field=='request_bindings': add"),
        'credential': ('grouping.py', 'if has_direct and credential_file and ssh_transport:'),
        'request': ('grouping.py', "if has_direct and execution and any"),
        'web': ('grouping.py', "if len(members)>1 and shared['flow_bindings'] and web:"),
        'host': ('grouping.py', "if has_direct: return"),
        'valid_direct': ('grouping.py', 'valid_direct=any('),
        'level': ('grouping.py', "level=('E1'"),
        'retention': ('grouping.py', "elif finite and len(members)>1 and level in"),
        'questions': ('grouping.py', "questions=['A shared high-level purpose"),
        'supporting_alerts': ('grouping.py', 'source_relation_ids=source_relations,supporting_alert_ids='),
        'pair_checks': ('grouping.py', 'pair_checks=[dict('),
        'identity_skip': ('evidence.py', 'if not kind: return []'),
        'positive_partition': ('evidence.py', 'is_negative=('),
    }
    return {key: loc(root, *value) for key, value in anchors.items()}


class Audit:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.proto = self.root / 'outputs/attack_step_offline_prototype_20261022'
        self.eval = self.root / 'outputs/attack_step_independent_evaluation_20261022'
        main = self.proto / 'attack_step_semantic_output.json'
        if sha(main) != EXPECTED_SHA:
            raise ValueError('BLOCKED: prototype output SHA mismatch')
        self.output = read(main)
        self.ledger = lines(self.proto / 'candidate_ledger.jsonl')
        self.manifest = read(self.proto / 'input_manifest.json')
        self.s8 = read(self.manifest['paths']['stage8'])
        self.s9 = read(self.manifest['paths']['stage9'])
        ev = self.s8['evidence']
        self.stages = {x['stage_id']: x for x in self.s8['stages']['stages']}
        self.alerts = {x['alert_id']: x for x in self.s8['alerts']}
        self.claims = {x['claim_id']: x for x in ev['claims']}
        self.decisions = {x['candidate_id']: x for x in ev['decisions']}
        self.accepted = {k: v for k, v in self.decisions.items() if v['relation_type'] != 'NO_RELATION'}
        self.contexts = {x['context_identity_id']: x for x in ev['context_postings']}
        self.obs = {x['observation_id']: x for x in ev['trace']['observations']}
        self.raw = {x['pointer_id']: x for x in ev['trace']['raw_pointers']}
        self.validations = {x['validation_id']: x for x in ev['trace']['validations']}
        self.descriptors = {x['stage_id']: x for x in read(self.proto / 'stage_descriptors.json')}
        self.groups = {x['semantic_step_id']: x for x in self.output['semantic_groups']}
        self.candidates = [x for x in self.ledger if x['decision'] == 'CANDIDATE']
        self.locations = source_locations(self.root)
        self.chain_owner = {sid: c['chain_id'] for c in self.s9['chains'] for sid in c['stage_ids']}
        self.owner = {aid: sid for sid, st in self.stages.items() for aid in st['alert_ids']}
        self.evidence_indexes = dict(stage=self.stages, claim=self.claims, relation_decision=self.decisions,
            context_posting=self.contexts, observation=self.obs, raw_pointer=self.raw, validation=self.validations,
            behavior_annotation={x['alert_id']: x for x in self.s8['stages']['behaviors']})
        # Native semantics are computed without GT or evaluation classifications.
        self.native = {x['candidate_id']: self.native_features(x) for x in self.candidates}
        self.relation_semantics = self.audit_relations_native()
        self.by_relation = {x['relation_id']: x for x in self.relation_semantics}
        self.origins = self.static_origin_paths()
        self.semantic_occurrences = self.classify_all_positive_evidence()
        # Only now attach offline evaluation labels. Nothing is fed to v1.
        self.truth = {x['proposal_id']: x for x in lines(self.eval / 'proposal_gt_classification.jsonl')}
        self.risk = read(self.eval / 'cross_gt_risk_analysis.json')
        self.risk_rows = {x['proposal_id']: x for x in self.risk['proposals']}
        assert len(self.ledger) == 129 and len(self.candidates) == 28
        assert Counter(self.truth[x['candidate_id']]['classification'] for x in self.candidates) == {
            'EXACT_GT_STEP': 2, 'PURE_GT_SUBSET': 6, 'CROSS_GT_MIXED': 20}

    def member_alerts(self, members):
        return {aid for sid in members for aid in self.stages[sid]['alert_ids']}

    def valid_claim(self, claim):
        return bool(claim['valid'] and not claim['conflict_status'] and claim['observation_ids'] and all(
            self.validations[self.obs[o]['validation_id']]['valid'] and
            not self.validations[self.obs[o]['validation_id']]['conflict_status'] for o in claim['observation_ids']))

    def raw_record(self, aid):
        return self.alerts[aid]['raw_alert']

    def native_features(self, ledger):
        members = ledger['member_stage_ids']
        aids = self.member_alerts(members)
        relations = [self.accepted[rid] for rid in ledger['source_relation_ids']]
        claims = [self.claims[cid] for d in relations for cid in d['relation_claim_ids'] if self.valid_claim(self.claims[cid])]
        contexts = [c for c in self.contexts.values() if set(members) <= set(c['stage_ids'])]
        request_cover = []
        # Positive clue: complementary request initiator + descendant, same scoped
        # request and lineage, with every selected alert covered. This is a
        # composite *candidate* clue, not a proven closed activity boundary.
        for ctx in contexts:
            if ctx['context_type'] != 'REQUEST':
                continue
            covered = {m['alert_id'] for m in ctx['memberships'] if m['stage_id'] in members}
            app = sorted(a for a in aids if self.raw_record(a).get('operation') == 'ApplicationRequest')
            lineage = [c['claim_id'] for c in claims if c['evidence_type'] == 'PARENT_CHILD_PROCESS']
            # Do not parse commands, infer purpose, or copy GT operation labels.
            role_link = []
            for cid in lineage:
                c = self.claims[cid]
                for oid in c['observation_ids']:
                    ob = self.obs[oid]
                    for side, other in [('a', 'b'), ('b', 'a')]:
                        if ob['alert_' + side + '_id'] in app and c['role_' + side] == 'PARENT':
                            role_link.append(dict(claim_id=cid, observation_id=oid,
                                parent_alert_id=ob['alert_' + side + '_id'],
                                child_alert_id=ob['alert_' + other + '_id']))
            request_cover.append(dict(context_id=ctx['context_identity_id'],
                scoped_identity=ctx['scoped_identity'], covered_alert_ids=sorted(covered),
                all_selected_alerts_covered=covered >= aids,
                outside_stage_ids=sorted(set(ctx['stage_ids']) - set(members)),
                application_request_alert_ids=app, role_link=role_link,
                plausible_membership_clue=bool(len(members) == 2 and covered >= aids and role_link),
                reliable_closed_step_boundary=False,
                limitation='Scope also binds other actions; lineage and request propagation do not delimit actor purpose.'))
        files = defaultdict(list)
        for aid in sorted(aids):
            a = self.alerts[aid]
            if a.get('file'):
                files[a['file']].append(dict(alert_id=aid, stage_id=self.owner[aid],
                    operation=a['raw_alert'].get('operation'), file_hash=a['raw_alert'].get('file_hash'),
                    command=a.get('command'), provenance=a['field_provenance'].get('file')))
        types = sorted({c['evidence_type'] for c in claims})
        plausible = any(c['plausible_membership_clue'] for c in request_cover)
        related_members = {sid for d in relations for sid in [d['stage_a_id'], d['stage_b_id']]}
        related_alerts = {self.obs[o]['alert_' + side + '_id'] for c in claims
                          for o in c['observation_ids'] for side in ['a', 'b']}
        return dict(valid_relation_claim_ids=sorted({c['claim_id'] for c in claims}), accepted_evidence_types=types,
            accepted_relation_ids=sorted(d['candidate_id'] for d in relations),
            shared_context_posting_ids=sorted(c['context_identity_id'] for c in contexts),
            request_boundary_observations=request_cover,
            plausible_membership_evidence=plausible,
            reliable_membership_evidence=False, observable_closed_step_boundary=False,
            file_observations=dict(files),
            accepted_relation_incident_stage_ids=sorted(related_members),
            members_without_any_accepted_relation=sorted(set(members) - related_members),
            accepted_relation_witness_alert_ids=sorted(related_alerts),
            member_alerts_without_accepted_relation_witness=sorted(aids - related_alerts),
            actual_credential_use_proven=False,
            accepted_relation_qualifies_finite_description=bool(claims),
            relation_only_retention=bool(claims) and not plausible,
            lineage_only_relation_basis=bool(claims) and set(types) == {'PARENT_CHILD_PROCESS'} and not plausible,
            lineage_qualifying_witness_present='PARENT_CHILD_PROCESS' in types,
            session_only_retention=False, host_account_only_retention=False,
            flow_only_retention=self.groups[ledger['candidate_id']]['semantic_label'] == 'WEB_ACTIVITY_CANDIDATE',
            temporal=ledger['whole_group_check']['shared_context']['time_overlap'])

    def static_origin_paths(self):
        """Static provenance reconstruction from immutable source loop ordering.

        Not v1 execution: attach origins only to already emitted ledger keys.
        Source reasons are a sorted SET, not a chronological trace. Runtime
        timestamps were not recorded; first means source-order first insertion.
        """
        result = {x['candidate_id']: [] for x in self.ledger}
        keys = defaultdict(list)
        for x in self.ledger:
            keys[(tuple(x['member_stage_ids']), x['whole_group_check']['identity_hypothesis'])].append(x['candidate_id'])

        def attach(members, kind, rule, evidence, location):
            key = tuple(sorted(set(members))), kind
            for cid in keys.get(key, []):
                result[cid].append(dict(rule=rule, evidence=evidence, code_location=self.locations[location]))

        for x in self.ledger:
            if x['whole_group_check']['identity_hypothesis'] is None:
                if len(x['member_stage_ids']) == 1:
                    attach(x['member_stage_ids'], None, 'SINGLE_STAGE_REVIEW', x['member_stage_ids'], 'singleton')
                elif len(x['member_stage_ids']) == 2:
                    attach(x['member_stage_ids'], None, 'EXHAUSTIVE_PAIR_REVIEW',
                           {'member_stage_ids': x['member_stage_ids'], 'semantic_eligibility_test_at_entry': False}, 'pair')
        for d in self.decisions.values():
            attach([d['stage_a_id'], d['stage_b_id']], None, 'EXISTING_' + d['relation_type'],
                   {'relation_decision_id': d['candidate_id']}, 'relation')
        for c in self.contexts.values():
            if len(c['stage_ids']) > 1:
                attach(c['stage_ids'], None, 'EXISTING_' + c['context_type'] + '_BUCKET',
                       {'context_posting_id': c['context_identity_id'], 'identity': c['scoped_identity']}, 'context_bucket')
        buckets = defaultdict(set)
        for sid, st in self.stages.items():
            for field in ['flow_bindings', 'session_bindings', 'request_bindings', 'task_bindings']:
                for key in st[field]:
                    buckets[(field, key)].add(sid)
        for (field, key), members in sorted(buckets.items()):
            if len(members) > 1:
                ev = {'stage_binding_field': field, 'existing_binding_key': key}
                attach(members, None, 'EXISTING_' + field.upper() + '_BUCKET', ev, 'binding_bucket')
                if field == 'request_bindings':
                    attach(members, 'request', 'EXPLICIT_SAME_REQUEST_REVIEW', ev, 'explicit_request')
        assert not any(c['evidence_type'] == 'REQUEST_RESPONSE' for c in self.claims.values())
        for x in self.ledger:
            paths = result[x['candidate_id']]
            assert paths and {p['rule'] for p in paths} == set(x['candidate_generation_reason']), x['candidate_id']
        return result

    def audit_relations_native(self):
        records = []
        for rid, d in self.accepted.items():
            pair = {d['stage_a_id'], d['stage_b_id']}
            exact_pair = next(x for x in self.candidates if set(x['member_stage_ids']) == pair)
            f = self.native[exact_pair['candidate_id']]
            primary = self.claims[d['primary_claim_id']]
            typ = primary['evidence_type']
            if f['plausible_membership_evidence']:
                verdict = 'SAME_STEP_COMPATIBLE'
                reason = 'Full selected-alert request coverage + native ApplicationRequest parent + child observations support a joint candidate clue; request scope extends outside the pair, so no safe whole-step boundary or P1 confirmation follows.'
            elif typ in {'AUTH_ESTABLISH_USE', 'CONNECTION_ESTABLISH_ACCEPT', 'OBJECT_HANDOFF'}:
                verdict = 'CROSS_STEP_PROGRESSION'
                reason = {'AUTH_ESTABLISH_USE': 'ESTABLISH/USE binds authentication lifecycle to later host execution, not an action identity.',
                          'CONNECTION_ESTABLISH_ACCEPT': 'INITIATE/ACCEPT binds transport endpoints; remote acceptance is distinct from the initiating host action.',
                          'OBJECT_HANDOFF': 'PRODUCE/CONSUME binds separate requests through an intermediate object; it does not equate their purpose.'}[typ]
            elif typ in {'SAME_TRUSTED_CONNECTION', 'SAME_PROCESS_INSTANCE'}:
                verdict = 'ASSOCIATION_ONLY'
                reason = 'A valid shared connection/process instance establishes association. The instance persists across different observed operations and carries no high-level purpose boundary.'
            elif typ == 'PARENT_CHILD_PROCESS':
                verdict = 'UNDETERMINED'
                reason = 'PARENT/CHILD identifies process ancestry, including process reuse across operations. Both intra-step binding and inter-step progression remain possible; native roles do not identify a high-level step boundary.'
            else:
                verdict = 'UNDETERMINED'
                reason = 'No approved purpose or closed membership boundary is encoded by this relation.'
            claim_rows = []
            for cid in d['relation_claim_ids']:
                c = self.claims[cid]
                covered = {self.obs[o]['alert_' + side + '_id'] for o in c['observation_ids'] for side in ['a', 'b']}
                claim_rows.append(dict(claim_id=cid, evidence_type=c['evidence_type'], semantic_class=c['semantic_class'],
                    role_a=c['role_a'], role_b=c['role_b'], identity=c['identity'], valid=self.valid_claim(c),
                    observation_count=len(c['observation_ids']), covered_alert_ids=sorted(covered),
                    missing_member_alert_ids=sorted(self.member_alerts(pair) - covered)))
            records.append(dict(relation_id=rid, member_stage_ids=sorted(pair), relation_type=d['relation_type'],
                direction_claim=d['direction_claim'], primary_claim_id=d['primary_claim_id'], primary_evidence_type=typ,
                classification=verdict, why=reason, claims=claim_rows,
                candidate_id=exact_pair['candidate_id'], existing_stage8_relation_error_implied=False,
                sufficient_for_same_step_confirmation=False,
                semantic_judgment_uses_gt=False))
        return records

    def claim_category(self, cid, candidate_id):
        c = self.claims[cid]
        typ = c['evidence_type']
        f = self.native[candidate_id]
        if typ in {'PARENT_CHILD_PROCESS', 'SAME_SCOPED_REQUEST'} and f['plausible_membership_evidence']:
            return 'SAME_STEP_EVIDENCE', 'JOINT_REQUEST_PARENT_CHILD_FULL_SELECTED_COVERAGE; conditional on composite witnesses, not sufficient alone or a closed boundary.'
        if typ in {'AUTH_ESTABLISH_USE', 'CONNECTION_ESTABLISH_ACCEPT', 'OBJECT_HANDOFF'}:
            return 'CROSS_STEP_RELATION', 'Native complementary lifecycle/transport/handoff roles establish progression, not membership.'
        if typ in {'PARENT_CHILD_PROCESS', 'SAME_PROCESS_INSTANCE'}:
            return 'AMBIGUOUS', 'Ancestry/process instance identifies a relationship; high-level step boundary remains undetermined.'
        if typ in {'SAME_URL', 'SHARED_PROCESS_DESCRIPTOR', 'SHARED_FILE_PATH'}:
            return 'SEMANTIC_SIMILARITY_ONLY', 'Shared lexical descriptor/path does not attest object consumption or a common purpose.'
        return 'SHARED_CONTEXT_ONLY', 'Scoped context/endpoint/host/account identity establishes shared environment, not activity membership.'

    def classify_all_positive_evidence(self):
        all_rows = []
        self.occurrence_by_candidate = {}
        for x in self.candidates:
            cid = x['candidate_id']
            relevant = {r['target_id'] for r in x['evidence_items'] if r['kind'] == 'claim'}
            parents = defaultdict(set)
            for claim_id in relevant:
                c = self.claims[claim_id]
                for oid in c['observation_ids']:
                    ob = self.obs[oid]
                    parents[('observation', oid)].add(claim_id)
                    parents[('validation', ob['validation_id'])].add(claim_id)
                    for pid in ob['raw_pointer_ids']:
                        parents[('raw_pointer', pid)].add(claim_id)
            candidate_rows = []
            for index, ref in enumerate(x['positive_evidence']):
                kind, target = ref['kind'], ref.get('target_id')
                if kind in self.evidence_indexes:
                    assert target in self.evidence_indexes[kind]
                parent_claims = set(parents[(kind, target)])
                categories = set()
                if kind == 'claim':
                    parent_claims.add(target)
                    category, reason = self.claim_category(target, cid)
                elif kind == 'relation_decision':
                    d = self.decisions[target]
                    assert d['relation_type'] != 'NO_RELATION'
                    verdict = self.by_relation[target]['classification']
                    category = {'SAME_STEP_COMPATIBLE': 'SAME_STEP_EVIDENCE',
                                'CROSS_STEP_PROGRESSION': 'CROSS_STEP_RELATION',
                                'ASSOCIATION_ONLY': 'SHARED_CONTEXT_ONLY', 'UNDETERMINED': 'AMBIGUOUS'}[verdict]
                    reason = self.by_relation[target]['why']
                    # Pair compatibility must not endorse a larger candidate.
                    if len(x['member_stage_ids']) > 2 and category == 'SAME_STEP_EVIDENCE':
                        category, reason = 'AMBIGUOUS', 'Compatible internal pair does not cover/justify all expanded members.'
                    parent_claims.update(d['relation_claim_ids'])
                elif kind in {'observation', 'validation', 'raw_pointer'}:
                    categories = {self.claim_category(p, cid)[0] for p in parent_claims}
                    category = next(iter(categories)) if len(categories) == 1 else 'AMBIGUOUS'
                    reason = ('Trace inherits the scoped semantics of its parent claim(s); validity/resolution is not independent membership evidence.'
                              if len(categories) == 1 else 'Trace is reused by multiple semantic evidence roles, or lacks a unique parent; retain ambiguity.')
                elif kind == 'behavior_annotation':
                    category, reason = 'SEMANTIC_SIMILARITY_ONLY', 'Action label/annotation describes an operation, not a shared higher-level purpose.'
                elif kind in {'context_posting', 'auth_session_binding', 'context_binding', 'host_alias_binding', 'entity'}:
                    category, reason = 'SHARED_CONTEXT_ONLY', 'Typed shared context can span several operations and steps; standalone scope is not a step boundary.'
                elif kind == 'stage':
                    category, reason = 'AMBIGUOUS', 'Existing Action Stage and its local aggregation are facts; they do not attest cross-Stage membership.'
                else:
                    raise ValueError('Unreviewed positive evidence kind: ' + kind)
                row = dict(occurrence_id=f'{cid}/positive_evidence/{index}', candidate_id=cid,
                    ledger_pointer=f'/positive_evidence/{index}', evidence_ref=ref,
                    classification=category, rationale=reason, parent_claim_ids=sorted(parent_claims),
                    parent_semantic_categories=sorted(categories), classification_uses_gt=False,
                    independent_membership_proof=False)
                candidate_rows.append(row)
            self.occurrence_by_candidate[cid] = candidate_rows
            all_rows.extend(candidate_rows)
        return all_rows

    def verify_inputs(self):
        required_proto = ['attack_step_semantic_output.json', 'candidate_ledger.jsonl', 'stage_descriptors.json',
            'input_manifest.json', 'schema_validation.json', 'evidence_trace_validation.json']
        required_eval = ['proposal_gt_classification.jsonl', 'pairwise_evaluation.json', 'candidate_truth_analysis.json',
            'p1_gate_diagnosis.json', 'four_case_evaluation.json', 'cross_gt_risk_analysis.json',
            'status_calibration_matrix.json', 'recoverability_analysis.json', 'observation_binding_review.json']
        checks = []
        ps = read(self.proto / 'acceptance_seal.json')
        es = read(self.eval / 'evaluation_seal.json')
        assert sha(self.proto / 'artifact_manifest.json') == ps['artifact_manifest_sha256']
        assert sha(self.proto / 'prototype_code_manifest.json') == ps['code_manifest_sha256']
        assert sha(self.eval / 'evaluation_artifact_manifest.json') == es['artifact_manifest_sha256']
        for folder, manifest, names in [(self.proto, read(self.proto / 'artifact_manifest.json'), required_proto),
                                        (self.eval, read(self.eval / 'evaluation_artifact_manifest.json'), required_eval)]:
            for name in names:
                path = folder / name
                value = read(path) if path.suffix == '.json' else lines(path)
                digest = sha(path)
                assert digest == manifest[name], str(path)
                checks.append(dict(path=str(path), sha256=digest, matches_seal=True, parsed=True,
                                   record_count=len(value) if isinstance(value, list) else None))
        for key, path in self.manifest['paths'].items():
            digest = sha(path)
            assert digest == self.manifest['digests'][key], key
            checks.append(dict(path=path, sha256=digest, matches_input_manifest=True))
        for rel, digest in read(self.proto / 'prototype_code_manifest.json')['files'].items():
            path = self.root / rel
            assert sha(path) == digest, rel
            checks.append(dict(path=str(path), sha256=digest, matches_frozen_prototype_code=True))
        # Resolve every raw trace pointer in isolation. No grouping or pipeline execution.
        for p in self.raw.values():
            ref = p['raw_pointer']
            pointer(self.alerts[ref['alert_id']]['raw_alert'], ref['pointer'])
        assert read(self.proto / 'schema_validation.json')['valid'] is True
        assert read(self.proto / 'evidence_trace_validation.json')['resolved_reference_occurrences'] == 36602
        return dict(mode='AUDIT_ONLY', prototype_output_sha256=EXPECTED_SHA,
            PROTOTYPE_OUTPUT_SHA_VERIFIED=True, files=checks,
            frozen_schema_validation_read=True, frozen_evidence_trace_validation_read=True,
            trace_raw_pointer_count=len(self.raw), trace_raw_pointer_resolution_failures=0,
            prototype_executed=False, pipeline_executed=False, source_inspection_only=True,
            population=dict(total_proposals=len(self.ledger), candidate_count=len(self.candidates),
                classification_counts=dict(Counter(self.truth[x['candidate_id']]['classification'] for x in self.candidates))))

    def retention_path(self, x):
        cid = x['candidate_id']
        group = self.groups[cid]
        label = group['semantic_label']
        branch = {'CREDENTIAL_ACTIVITY_CANDIDATE': 'credential', 'REQUEST_EXECUTION_CANDIDATE': 'request',
                  'WEB_ACTIVITY_CANDIDATE': 'web', 'HOST_ACTIVITY_CANDIDATE': 'host'}[label]
        f = self.native[cid]
        flat = [self.alerts[a] for a in x['supporting_alert_ids']]
        evidence = dict(valid_relation_ids=x['source_relation_ids'], valid_relation_claim_ids=f['valid_relation_claim_ids'],
            evidence_level=x['evidence_level'], finite_description_branch=label,
            ssh_file_alert_ids=sorted(a['alert_id'] for a in flat if isinstance(a.get('file'), str) and '/.ssh/' in a['file'].replace('\\', '/')),
            ssh_transport_alert_ids=sorted(a['alert_id'] for a in flat if a.get('dst_port') == 22),
            request_bound_stage_ids=sorted(s for s in x['member_stage_ids'] if self.stages[s]['request_bindings']),
            execution_stage_ids=sorted(s for s in x['member_stage_ids'] if self.stages[s]['behavior'] in {'EXECUTION', 'FILE_ACTIVITY'}),
            shared_flow_bindings=x['whole_group_check']['shared_context']['flow_bindings'],
            p1_complete=x['whole_group_check']['p1']['complete'], identity_hypothesis=x['whole_group_check']['identity_hypothesis'],
            induced_components=x['whole_group_check']['induced_components'], chain_ids=group['member_chain_ids'])
        return dict(candidate_id=cid,
            RETENTION_RULE='finite description AND member_count>1 AND evidence_level in E1/E2/E3',
            RETENTION_EVIDENCE=evidence, code_location=self.locations['retention'],
            finite_description_code_location=self.locations[branch], decision_reason=x['decision_reason'],
            MISSING_REJECTION_GUARD='No candidate-level purpose/membership coverage or observable activity-boundary requirement. P1 failure is a question; generic identity_kind=None bypasses identity contradiction checks. Any valid internal accepted relation can qualify the whole bucket.',
            missing_guard_scope='Candidate eligibility/retention, not a proposal-pool rejection requirement; no change made.',
            shared_host_or_account_direct_predicate=False, shared_session_direct_predicate=False,
            diagnostic_checks=dict(all_pairs_checked=x['whole_group_check']['all_pairs_checked'],
                identity_check_bypassed=x['whole_group_check']['identity_hypothesis'] is None,
                purpose_failure_is_question=True, refs_resolved=x['whole_group_check']['unresolved_reference_count'] == 0),
            code_locations={k: self.locations[k] for k in ['valid_direct', 'level', 'identity_skip', 'pair_checks', 'questions', 'supporting_alerts', 'positive_partition']})

    def rows(self):
        rows = []
        for x in self.candidates:
            cid = x['candidate_id']
            f, gt = self.native[cid], self.truth[cid]
            members = x['member_stage_ids']
            group = self.groups[cid]
            paths, retain = self.origins[cid], self.retention_path(x)
            shared = x['whole_group_check']['shared_context']
            contexts = [self.contexts[k] for k in f['shared_context_posting_ids']]
            claims = [self.claims[k] for k in f['valid_relation_claim_ids']]
            by_category = {cat: [r['occurrence_id'] for r in self.occurrence_by_candidate[cid] if r['classification'] == cat] for cat in CATEGORIES}
            process = set(self.stages[members[0]]['process_entities'])
            for sid in members[1:]:
                process &= set(self.stages[sid]['process_entities'])

            def shared_descriptor(field, id_field):
                collections = [{b[id_field]: b for b in self.descriptors[sid][field]} for sid in members]
                keys = set(collections[0])
                for coll in collections[1:]:
                    keys &= set(coll)
                return [collections[0][key] for key in sorted(keys)]

            primary = None
            secondary = []
            if gt['classification'] == 'CROSS_GT_MIXED':
                primary = ROOTS['H'] if len(members) > 2 else ROOTS['D'] if f['flow_only_retention'] else ROOTS['A']
                secondary = [ROOTS['I'], ROOTS['K']]
                if f['relation_only_retention']:
                    secondary.append(ROOTS['G'])
                if 'PARENT_CHILD_PROCESS' in f['accepted_evidence_types']:
                    secondary.append(ROOTS['B'])
                if f['flow_only_retention']:
                    secondary.append(ROOTS['F'])
                if paths[0]['rule'] == 'EXHAUSTIVE_PAIR_REVIEW':
                    secondary.append(ROOTS['J'])
                if primary == ROOTS['H'] and f['relation_only_retention']:
                    secondary.append(ROOTS['A'])
            row = dict(candidate_id=cid, prototype_status='CANDIDATE', member_stage_ids=members,
                member_chain_ids=group['member_chain_ids'], gt_stage_ids=gt['gt_stage_ids'], gt_classification=gt['classification'],
                candidate_generation_sources=x['candidate_generation_reason'], source_relation_ids=x['source_relation_ids'],
                relation_types=sorted({self.accepted[k]['relation_type'] for k in x['source_relation_ids']}),
                shared_host=shared['host_entities'], shared_account=shared['account_entities'], shared_process=sorted(process),
                process_lineage=[c['claim_id'] for c in claims if c['evidence_type'] == 'PARENT_CHILD_PROCESS'],
                shared_flow=shared['flow_bindings'],
                shared_connection=shared_descriptor('connection', 'projection_id'),
                shared_network_session=[dict(stage_id=sid, observations=self.descriptors[sid]['network_session']) for sid in members if self.descriptors[sid]['network_session']],
                shared_network_session_note='Only explicitly typed native network_session; mixed upstream session_bindings are kept separately.',
                shared_session_bindings=shared['session_bindings'],
                shared_auth_session=shared_descriptor('auth_session', 'projection_id'),
                shared_request=shared['request_bindings'],
                shared_object=[c['context_identity_id'] for c in contexts if c['context_type'] == 'OBJECT'],
                temporal_features=dict(interval_overlap=shared['time_overlap'],
                    stage_intervals=[{k: self.stages[sid][k] for k in ['stage_id', 'start_time', 'end_time']} for sid in members],
                    minimum_observed_stage_gap_seconds=self.risk_rows.get(cid, {}).get('minimum_observed_stage_gap_seconds'),
                    temporal_proximity_is_membership_proof=False),
                semantic_labels=[group['semantic_label']], evidence_levels=[x['evidence_level']],
                direct_binding_evidence=[dict(claim_id=c['claim_id'], evidence_type=c['evidence_type'], identity=c['identity'],
                    role_a=c['role_a'], role_b=c['role_b'], observation_ids=c['observation_ids']) for c in claims],
                direct_binding_evidence_note='Existing accepted relation claims and native role witnesses, not automatically same-step membership. Some are associative/context claims accepted alongside a primary relation.',
                relation_evidence=[self.by_relation[k] for k in x['source_relation_ids']],
                context_evidence=f['shared_context_posting_ids'], semantic_evidence=by_category['SEMANTIC_SIMILARITY_ONLY'],
                candidate_entry_reason=paths[0]['rule'], candidate_retention_reason=retain['RETENTION_RULE'],
                same_step_support=by_category['SAME_STEP_EVIDENCE'],
                cross_step_relation_support=by_category['CROSS_STEP_RELATION'], ambiguous_support=by_category['AMBIGUOUS'],
                positive_evidence_category_counts={k: len(v) for k, v in by_category.items()},
                first_candidate_admission_rule=paths[0]['rule'], code_location=paths[0]['code_location'],
                FIRST_CANDIDATE_ADMISSION_POINT=paths[0], FIRST_ADMISSION_RULE=paths[0]['rule'],
                FIRST_ADMISSION_EVIDENCE=paths[0]['evidence'], FIRST_ADMISSION_CODE_LOCATION=paths[0]['code_location'],
                RETENTION_RULE=retain['RETENTION_RULE'], RETENTION_EVIDENCE=retain['RETENTION_EVIDENCE'],
                MISSING_REJECTION_GUARD=retain['MISSING_REJECTION_GUARD'],
                contamination_root_cause=primary, PRIMARY_ROOT_CAUSE=primary, SECONDARY_ROOT_CAUSES=secondary,
                audit_conclusion=('CROSS_STEP_RELATION_MISUSED_FOR_SAME_STEP_CANDIDACY' if f['relation_only_retention'] else 'SHARED_FLOW_AND_WEB_SHAPE_PROMOTED_TO_CANDIDATE')
                    if gt['classification'] == 'CROSS_GT_MIXED' else
                    'PLAUSIBLE_COMPOSITE_MEMBERSHIP_CLUE_WITHOUT_CLOSED_STEP_BOUNDARY' if f['plausible_membership_evidence'] else
                    'GT_PURITY_ALONE_DOES_NOT_VALIDATE_THE_MECHANISM',
                native_semantics=f, retention_path=retain,
                contamination_locus='RETENTION' if primary else None,
                risk_context_exposures=self.risk_rows.get(cid, {}).get('risk_context_flags', {}),
                evidence_semantics_derived_before_gt_join=True)
            rows.append(row)
        return rows

    def enumeration(self):
        stats = {}
        first = Counter()
        for x in self.ledger:
            first[self.origins[x['candidate_id']][0]['rule']] += 1
        sources = sorted({s for x in self.ledger for s in x['candidate_generation_reason']})
        for source in sources:
            all_rows = [x for x in self.ledger if source in x['candidate_generation_reason']]
            cand = [x for x in all_rows if x['decision'] == 'CANDIDATE']
            c = Counter(self.truth[x['candidate_id']]['classification'] for x in cand)
            stats[source] = dict(PROPOSAL_COUNT=len(all_rows), FIRST_SOURCE_PROPOSAL_COUNT=first[source],
                CANDIDATE_COUNT=len(cand), GT_PURE_COUNT=c['EXACT_GT_STEP'] + c['PURE_GT_SUBSET'],
                EXACT_GT_COUNT=c['EXACT_GT_STEP'], PURE_SUBSET_COUNT=c['PURE_GT_SUBSET'], GT_MIXED_COUNT=c['CROSS_GT_MIXED'],
                candidate_ids=[x['candidate_id'] for x in cand])
            first_cand = [x for x in cand if self.origins[x['candidate_id']][0]['rule'] == source]
            first_truth = Counter(self.truth[x['candidate_id']]['classification'] for x in first_cand)
            stats[source]['FIRST_SOURCE_CANDIDATES'] = dict(CANDIDATE_COUNT=len(first_cand),
                GT_PURE_COUNT=first_truth['EXACT_GT_STEP'] + first_truth['PURE_GT_SUBSET'],
                GT_MIXED_COUNT=first_truth['CROSS_GT_MIXED'], candidate_ids=[x['candidate_id'] for x in first_cand])
        context_rows = [x for x in self.ledger if any(s.endswith('_BUCKET') for s in x['candidate_generation_reason'])]
        relation_rows = [x for x in self.ledger if any(s in {'EXISTING_DIRECTED_EDGE', 'EXISTING_UNDIRECTED_EDGE', 'EXISTING_NO_RELATION'} for s in x['candidate_generation_reason'])]
        expansions = [x for x in self.ledger if len(x['member_stage_ids']) > 2]
        return dict(TOTAL_STAGE_PAIRS=len(self.stages) * (len(self.stages) - 1) // 2,
            TOTAL_PROPOSALS=len(self.ledger), PAIR_ENUMERATION_PROPOSALS=stats['EXHAUSTIVE_PAIR_REVIEW']['PROPOSAL_COUNT'],
            CONTEXT_BUCKET_PROPOSALS=len(context_rows), RELATION_DERIVED_PROPOSALS=len(relation_rows),
            ACCEPTED_RELATION_DERIVED_PROPOSALS=sum(any(s in {'EXISTING_DIRECTED_EDGE', 'EXISTING_UNDIRECTED_EDGE'} for s in x['candidate_generation_reason']) for x in self.ledger),
            MULTI_STAGE_EXPANSION_PROPOSALS=len(expansions),
            MULTI_STAGE_EXPANSION_CANDIDATES=sum(x['decision'] == 'CANDIDATE' for x in expansions),
            sources=stats, first_source_proposal_counts=dict(first),
            counts_overlap=True, overlap_definition='Any-origin source counts overlap. First-source counts partition emitted proposals including identity-kind variants.',
            CONTAMINATION_SOURCE='RETENTION_DOMINANT',
            rationale='Enumeration intentionally retrieves unknown and NO_RELATION pairs for review. Entry alone asserts no membership. The finite-description/E2-E3 status gate converts 20 mixed proposals into CANDIDATE without a membership boundary. Bucket expansion supplies 6 of them.',
            statistical_limit='Single fixed population; this audit does not estimate out-of-sample correctness.')

    def counterfactuals(self, rows):
        predicates = {
            'remove_relation_only': lambda r: r['native_semantics']['relation_only_retention'],
            'remove_lineage_only': lambda r: r['native_semantics']['lineage_only_relation_basis'],
            'remove_same_session_only': lambda r: r['native_semantics']['session_only_retention'],
            'remove_same_flow_only': lambda r: r['native_semantics']['flow_only_retention'],
            'remove_host_account_only': lambda r: r['native_semantics']['host_account_only_retention'],
            'require_membership_evidence': lambda r: not r['native_semantics']['plausible_membership_evidence'],
            'require_same_chain': lambda r: len(r['member_chain_ids']) != 1,
            'require_observable_step_boundary': lambda r: not r['native_semantics']['observable_closed_step_boundary'],
        }
        definitions = {
            'remove_relation_only': 'Remove when a valid accepted internal relation qualifies the finite description without any independently audited composite membership clue. Generic lexical/request presence is descriptive. The provisional full-coverage request/role composite is excluded even though it is not a reliable closed boundary.',
            'remove_lineage_only': 'Remove only if all currently valid accepted relation claims are PARENT_CHILD_PROCESS and no independent composite membership clue exists; having any lineage exposure is not enough.',
            'remove_same_session_only': 'Remove only if shared session alone causes Candidate retention. No such implemented branch; context bucket origin/exposure alone does not count.',
            'remove_same_flow_only': 'Remove WEB_ACTIVITY branch: shared flow + per-member web shape, no accepted binding. Only refers to binding evidence, not to literal absence of web labels.',
            'remove_host_account_only': 'Remove only if host/account alone causes retention. No such implemented branch.',
            'require_membership_evidence': 'Lenient candidate-clue scenario: require the audited composite scoped request + ApplicationRequest parent/child role linkage + full selected-alert coverage. This is NOT an approved eligibility rule; S05 object use remains unproven.',
            'require_same_chain': 'Remove cross-Chain candidates for comparison only; Chain partitions relatedness and are not step truth.',
            'require_observable_step_boundary': 'Require a reliable, closed, whole-member high-level activity boundary. Current native evidence does not establish one; an externally shared request identity is insufficient.',
        }
        scenarios = []
        for name, predicate in predicates.items():
            # Predicate sees native/ledger fields only; GT counts are post-hoc.
            removed = [r for r in rows if predicate(r)]
            kept = [r for r in rows if not predicate(r)]
            scenarios.append(dict(name=name, definition=definitions[name],
                removed_candidate_ids=[r['candidate_id'] for r in removed],
                kept_candidate_ids=[r['candidate_id'] for r in kept],
                removed_counts={t: sum(r['gt_classification'] == t for r in removed) for t in TRUTH},
                kept_counts={t: sum(r['gt_classification'] == t for r in kept) for t in TRUTH},
                loses_gt_true_candidates=any(r['gt_classification'] == 'EXACT_GT_STEP' for r in removed),
                loses_pure_subset_candidates=any(r['gt_classification'] == 'PURE_GT_SUBSET' for r in removed),
                recommended_as_production_filter=False,
                safety_assessment='Set-only sensitivity, not causal re-execution: alternative branches were not replayed. Losing current positives, incomplete purpose semantics and external generalization remain material risks.'))
        return dict(mode='FROZEN_LEDGER_SET_ANALYSIS_ONLY', prototype_rerun=False, scenarios=scenarios,
            only_definition='Only the actually qualifying binding family; descriptive co-occurrence is distinguished from decisive evidence. No exposure-based session/host removal.',
            reliable_membership_sensitivity=dict(removed_counts={t: sum(r['gt_classification'] == t for r in rows) for t in TRUTH},
                reason='Requiring reliable membership rather than a plausible clue removes all 28; no approved activity-boundary proof is present.'),
            selection_by_gt_metrics=False)

    def risk_analysis(self, rows):
        mixed = [r for r in rows if r['gt_classification'] == 'CROSS_GT_MIXED']
        records = []
        for key, expected in self.risk['contexts_by_status']['CANDIDATE'].items():
            selected = [r for r in mixed if r['risk_context_exposures'].get(key)]
            assert len(selected) == expected, key
            notes = {
                'process_lineage': 'Parent-child is a real relationship; it is ambiguous with respect to a higher-level purpose. Inspect claim-only count separately from the 8 exposures.',
                'shared_session': 'SESSION_IS_CONTEXT_NOT_STEP_BOUNDARY. Session buckets can retrieve groups but shared session is not a direct finite-description retention predicate.',
                'same_flow': 'Flow co-occurs in 6 mixed candidates; only WEB_ACTIVITY finite-description branch directly promotes flow+web shape.',
                'same_host': 'Host alias/scope observations are real; host itself never triggers the Candidate retention branch.',
                'same_account': 'Scoped account is reused across native actions. Account itself never triggers finite-description candidacy.',
                'authentication_lifecycle': 'AUTHENTICATION_RELATION ESTABLISH/USE links authentication to later execution. It does not prove ACTION_IDENTITY.',
                'incoming_ssh': 'TRANSPORT_RELATION INITIATE/ACCEPT concerns endpoint connection roles; destination authentication and source action are not equated.',
                'outbound_connection': 'SAME_TRUSTED_CONNECTION associates host execution with outbound network observations. No typed C2-purpose or high-level membership claim is present; host-action→network progression is possible.',
                'temporal_interval_overlap': 'Time overlap is descriptive, not an activity identity.',
            }
            records.append(dict(family=key, cross_gt_exposure_count=len(selected), candidate_ids=[r['candidate_id'] for r in selected],
                qualifying_binding_witness_count=sum(
                    r['native_semantics']['flow_only_retention'] if key == 'same_flow' else
                    r['native_semantics']['lineage_qualifying_witness_present'] if key == 'process_lineage' else False for r in selected),
                sole_qualifying_binding_family_count=sum(
                    r['native_semantics']['flow_only_retention'] if key == 'same_flow' else
                    r['native_semantics']['lineage_only_relation_basis'] if key == 'process_lineage' else False for r in selected),
                direct_context_predicate_count=sum(r['native_semantics']['flow_only_retention'] for r in selected) if key == 'same_flow' else 0,
                session_bucket_first_retrieval_count=sum('SESSION' in r['FIRST_ADMISSION_RULE'] for r in selected) if key == 'shared_session' else 0,
                analysis=notes[key]))
        return records

    def controls(self, rows):
        records = []
        for r in rows:
            if r['gt_classification'] != 'EXACT_GT_STEP':
                continue
            f = r['native_semantics']
            aids = self.member_alerts(r['member_stage_ids'])
            if f['plausible_membership_evidence']:
                worthwhile = 'Keep the composite request/parent-child/coverage clue as provisional SAME_STEP_EVIDENCE. Neither request identity nor parent-child is sufficient alone.'
                difference = 'All 10 selected alerts share the scoped request, and native ApplicationRequest is a PARENT of the child. This differentiates the local pair from current cross-GT lineage pairs without reading GT.'
                limit = 'The very same scoped request also covers upload observations outside the pair; the child process instance also executes credential-file operations. Selecting a clean subset does not prove its high-level activity boundary.'
            else:
                worthwhile = 'File identity observations and lineage are worth retaining as association clues. They do not attest a credential-read→actual credential-use purpose binding.'
                difference = 'Both members observe the same file path; 8 read-side EDR alerts and 4 SSH-side alerts have the same file hash. The SSH command explicitly names that path with -i. These are richer object-use clues than session alone.'
                limit = 'Native operation is NetworkConnection rather than credential consumption. Host-audit reads include exec/FileModify records. Shared pathname/hash or a command argument does not prove actual use/authentication; no accepted credential object-use claim binds all members.'
            comparable = [x for x in rows if x['gt_classification'] == 'CROSS_GT_MIXED' and
                          bool(set(x['native_semantics']['accepted_evidence_types']) & set(f['accepted_evidence_types']))]
            records.append(dict(candidate_id=r['candidate_id'], gt_stage_ids=r['gt_stage_ids'],
                member_stage_ids=r['member_stage_ids'], member_alert_count=len(aids),
                admission=self.origins[r['candidate_id']][0], retention=r['retention_path'],
                request_boundary_observations=f['request_boundary_observations'],
                file_observations=f['file_observations'], direct_binding_evidence=r['direct_binding_evidence'],
                contexts={k: r[k] for k in ['shared_host', 'shared_account', 'shared_process', 'process_lineage',
                    'shared_flow', 'shared_connection', 'shared_auth_session', 'shared_session_bindings', 'shared_request']},
                outside_process_reuse=[dict(process_entity_id=pid, outside_stage_ids=sorted(
                    sid for sid, st in self.stages.items() if sid not in r['member_stage_ids'] and pid in st['process_entities']))
                    for pid in sorted({p for sid in r['member_stage_ids'] for p in self.stages[sid]['process_entities']})],
                native_credential_fingerprint_observations=[dict(alert_id=a['alert_id'],
                    operation=a['raw_alert'].get('operation'), key_fingerprint=a['raw_alert'].get('key_fingerprint'),
                    source_namespace=a['source_namespace'], inside_candidate=a['alert_id'] in aids,
                    file_hash_equivalence_attested=False) for a in self.alerts.values() if a['raw_alert'].get('key_fingerprint')],
                same_step_evidence_occurrences=r['same_step_support'], useful_signal=worthwhile,
                local_observable_difference=difference, observed_local_difference_exists=True,
                safe_generalizable_step_boundary_distinction=False,
                limitation=limit, comparison_candidate_ids=[x['candidate_id'] for x in comparable],
                observation_summary=[dict(alert_id=a, stage_id=self.owner[a], native_operation=self.raw_record(a).get('operation'),
                    source_namespace=self.alerts[a]['source_namespace'], command=self.alerts[a].get('command'),
                    request_id=self.raw_record(a).get('request_id'), raw_pointer_root='') for a in sorted(aids)],
                verdict='CURRENT_FEATURES_CANNOT_DISTINGUISH_SAFE_PARENT_CHILD_SAME_STEP',
                verdict_scope='Safe high-level membership distinction, not a claim that raw feature values are identical. Candidate compatibility remains weaker than a reliable boundary.',
                p1_complete=False, actual_credential_use_proven=False))
        return dict(controls=records, safe_generalizable_difference_found=False,
            raw_feature_differences_exist=True, proposed_special_cases=[],
            file_hash_vs_key_fingerprint='Different semantic domains; no observed equivalence attests that the accepted public key is the source file. Do not treat unequal strings as a conflict or infer equality.',
            full_member_coverage_is_not_automatic_purpose_proof=True)

    def pure_subsets(self, rows):
        return dict(rows=[dict(candidate_id=r['candidate_id'], member_stage_ids=r['member_stage_ids'],
            gt_stage_ids=r['gt_stage_ids'], classification='GENERIC_SHARED_CONTEXT',
            secondary_classification='ENUMERATION_ARTIFACT', first_admission=r['FIRST_CANDIDATE_ADMISSION_POINT'],
            shared_flow=r['shared_flow'], source_relation_ids=r['source_relation_ids'],
            same_step_support=r['same_step_support'], semantic_labels=r['semantic_labels'],
            explanation='Pair enumeration happens to select two actions within one evaluation episode. Shared flow and web shape provide no exclusive purpose or full five-action episode boundary. No accepted intra-pair relation exists.',
            counterexample_candidate_ids=[x['candidate_id'] for x in rows if x['gt_classification'] == 'CROSS_GT_MIXED' and x['native_semantics']['flow_only_retention']],
            true_semantic_capability_established=False) for r in rows if r['gt_classification'] == 'PURE_GT_SUBSET'],
            conclusion='Six pure pairs are not six independent successful episode reconstructions; the same mechanism also retains five mixed flow/web proposals.')


def relation_matrix():
    return dict(terminology='Audit vocabulary only; frozen formal contract unchanged.',
        RELATION_EVIDENCE='Shows two observed actions are associated, ordered, or causally linked.',
        MEMBERSHIP_EVIDENCE='Explains a common bounded high-level activity/purpose with typed roles and whole-member coverage; a graph edge is not such an explanation.',
        rows=[dict(evidence=e, proves_relation=related, supports_same_step_candidate=candidate,
                   sufficient_alone_to_confirm=False, audit_semantic_role=role, rationale=why)
              for e, related, candidate, role, why in [
            ('Directed Stage Relation', True, 'CONDITIONAL_ON_ADDITIONAL_MEMBERSHIP_EVIDENCE', 'RELATION_EVIDENCE', 'Direction links actions; authentication, transport and object handoff cross distinct operations.'),
            ('Undirected Relation', True, 'NO_STANDALONE_MEMBERSHIP_SUPPORT', 'RELATION_EVIDENCE', 'Shared process/connection associates endpoints without a common high-level purpose.'),
            ('Parent-Child Process', True, 'CONDITIONAL_ON_COMMON_ACTIVITY_AND_ROLE_COVERAGE', 'RELATION_EVIDENCE/AMBIGUOUS_BOUNDARY', 'Process ancestry persists across file creation, reads and network usage.'),
            ('Shared Session', 'SHARED_LIFECYCLE_CONTEXT', 'NO_STANDALONE_MEMBERSHIP_SUPPORT', 'CONTEXT', 'Session lifetime spans several native operations; transport/session/action identity must be separated.'),
            ('Same Flow', 'NETWORK_CONTEXT', 'NO_STANDALONE_MEMBERSHIP_SUPPORT', 'CONTEXT', 'A flow carries different requests and detector activities; six pure pairs and mixed pairs share this mechanism.'),
            ('Same Host', 'ENVIRONMENT_ONLY', 'NO_STANDALONE_MEMBERSHIP_SUPPORT', 'CONTEXT', 'Authority scopes a machine, not an attacker purpose.'),
            ('Same Account', 'PRINCIPAL_CONTEXT', 'NO_STANDALONE_MEMBERSHIP_SUPPORT', 'CONTEXT', 'One principal operates across process and connection lifecycles.'),
            ('Request→Execution', 'IF_ROLE_BINDING_IS_OBSERVED', 'PLAUSIBLE_WITH_FULL_SCOPED_COVERAGE_AND_NATIVE_ROLE_LINK', 'PROVISIONAL_MEMBERSHIP_CLUE', 'One current pair has all selected alerts covered, but the request extends outside the pair. P1 is REQUEST_RESPONSE, not request→execution.'),
            ('Credential Object→Use', 'IF_OBJECT_CONSUMPTION_IS_OBSERVED', 'CONDITIONAL_ON_TYPED_ACTUAL_USE_AND_ACTIVITY_BOUNDARY', 'UNPROVEN_MEMBERSHIP_CLUE', 'Same pathname/hash and ssh -i naming do not attest actual credential consumption; no such accepted typed claim exists here.')]],
        frozen_confirmation_rule='Only complete authoritative scoped REQUEST_RESPONSE P1, complementary roles, all member alerts covered, connected accepted induced graph, one Chain, no conflicts and unique primary membership may confirm. Current claim count is zero.')


def design_constraints():
    return dict(PROTOTYPE_V2_JUSTIFIED=False, interpretation='No implementation/tuning authorization follows from this audit. Narrow provisional clues exist, but reliable high-level membership boundaries are not established.',
        minimal_abstraction='MEMBERSHIP_EVIDENCE_MODEL', prerequisite='STEP_BOUNDARY_MODEL',
        downstream_layers=['CANDIDATE_ADMISSION', 'CANDIDATE_RETENTION', 'GROUP_EXPANSION'],
        SEMANTIC_TAXONOMY_change_justified=False,
        required_design_properties=[
            'Distinguish diagnostic proposal retrieval from same-step eligibility; retain broad retrieval as reviewable unknowns.',
            'Represent relation and membership evidence separately. Validity, strength, observation count, or E2 cannot substitute for membership semantics.',
            'Specify observable activity purpose/boundary and complementary roles independent of GT, with negative and ambiguous evidence.',
            'Prove membership support for every expanded member; pair compatibility and one internal edge cannot certify a context bucket.',
            'Treat host/account/session/flow as context unless independent purpose evidence exists; never promote exposure alone.',
            'Audit native object consumption separately from pathname/hash agreement or a command argument.',
            'Preserve ambiguity and allow abstention; no forced grouping when boundary evidence is absent.',
            'Require independent, more varied evidence/annotations and holdout evaluation before any v2 implementation decision.'],
        forbidden_design_shortcuts=['GT IDs, fixed URLs/commands/paths', 'choose filter by current GT precision',
            'ban all cross-Chain candidates', 'parent-child implies membership', 'session equals step',
            'parse command to claim actual successful credential use', 'increase rules while membership remains unobservable'],
        existing_contract_and_P1_remain_frozen=True,
        NEXT_ACTION='DEFINE_OBSERVABLE_STEP_BOUNDARY')


def task_result(rows, immutable):
    mixed = [r for r in rows if r['gt_classification'] == 'CROSS_GT_MIXED']
    qualifying_lineage = sum(r['native_semantics']['lineage_qualifying_witness_present'] for r in mixed)
    return dict(TASK_RESULT='PASS' if immutable else 'FAIL', AUDIT_MODE='CANDIDATE_CONTAMINATION',
        PROTOTYPE_OUTPUT_SHA_VERIFIED=True, TOTAL_CANDIDATE_COUNT=len(rows),
        EXACT_GT_CANDIDATE_COUNT=sum(r['gt_classification'] == 'EXACT_GT_STEP' for r in rows),
        PURE_GT_SUBSET_CANDIDATE_COUNT=sum(r['gt_classification'] == 'PURE_GT_SUBSET' for r in rows),
        CROSS_GT_CANDIDATE_COUNT=len(mixed), CROSS_GT_CANDIDATES_AUDITED=len(mixed), PURE_CANDIDATES_AUDITED=len(rows) - len(mixed),
        ADMISSION_CONTAMINATION_COUNT=0, RETENTION_CONTAMINATION_COUNT=len(mixed), BOTH_CONTAMINATION_COUNT=0,
        RELATION_EVIDENCE_MISUSED_COUNT=sum(r['native_semantics']['relation_only_retention'] for r in mixed),
        SHARED_CONTEXT_OVER_ADMISSION_COUNT=sum(r['native_semantics']['flow_only_retention'] for r in mixed),
        PROCESS_LINEAGE_OVER_ADMISSION_COUNT=qualifying_lineage, SESSION_OVER_ADMISSION_COUNT=0,
        FLOW_OVER_ADMISSION_COUNT=sum(r['native_semantics']['flow_only_retention'] for r in mixed),
        SEMANTIC_OVER_ADMISSION_COUNT=sum(r['native_semantics']['flow_only_retention'] for r in mixed),
        GROUP_EXPANSION_CONTAMINATION_COUNT=sum(len(r['member_stage_ids']) > 2 for r in mixed),
        SAFE_GENERALIZABLE_DIFFERENCE_FOUND=False, PRIMARY_CONTAMINATION_ROOT_CAUSE=ROOTS['K'],
        SECONDARY_CONTAMINATION_ROOT_CAUSES=[ROOTS[k] for k in ['I', 'A', 'G', 'H', 'D', 'B', 'F', 'J']],
        GT_S04_DISTINGUISHABLE_WITH_OBSERVABLE_EVIDENCE=False, GT_S05_DISTINGUISHABLE_WITH_OBSERVABLE_EVIDENCE=False,
        CANDIDATE_ADMISSION_REDESIGN_REQUIRED=True, CANDIDATE_RETENTION_REDESIGN_REQUIRED=True,
        MEMBERSHIP_EVIDENCE_MODEL_REQUIRED=True, STEP_BOUNDARY_MODEL_REQUIRED=True,
        PROTOTYPE_CODE_MODIFIED=not immutable, CONTRACT_MODIFIED=not immutable, P1_MODIFIED=not immutable,
        DATASET_MODIFIED=not immutable, GROUND_TRUTH_MODIFIED=not immutable, STAGES_1_TO_9_MODIFIED=not immutable,
        PROTOTYPE_V2_JUSTIFIED=False, NEXT_ACTION='DEFINE_OBSERVABLE_STEP_BOUNDARY')


def integrity(output):
    before = read(output / 'protected_before.json')
    changed = []
    for name, digest in before.items():
        path = Path(name)
        if not path.is_file() or sha(path) != digest:
            changed.append(name)
    result = dict(protected_existing_file_count=len(before), changed_or_missing_files=changed,
        unchanged=not changed, before_manifest_sha256=sha(output / 'protected_before.json'),
        method='Compare pre-audit SHA256 inventory of existing source, frozen docs/outputs, ATTACK125 and GT. New audit-only files are additive.',
        checked_at=datetime.now(timezone.utc).isoformat())
    dump(output / 'integrity_verification.json', result)
    return not changed


def report(audit, rows, enum, counter, result, output):
    mixed = [r for r in rows if r['gt_classification'] == 'CROSS_GT_MIXED']
    categories = Counter(x['classification'] for x in audit.semantic_occurrences)
    text = f'''# Attack Step Candidate 污染专项审计

本轮为 AUDIT_ONLY，完成 28/28 Candidate、20/20 跨 GT、2 个精确对照和 6 个纯子集的逐项审计。主产物 SHA256 为 `{EXPECTED_SHA}`，与封存值一致。没有执行、修改或重生成 Prototype v1，也没有修改 Contract/P1/①～⑨/ATTACK125/GT。

审计结论：**RETENTION_DOMINANT**。跨 GT 的 20 个 Proposal 中，15 个依靠有效 accepted relation 获得有限描述，另外 5 个依靠共享 flow 与 Web 外形。它们进入 CANDIDATE 时均没有可靠的共同目的、完整活动边界证明。这里的 PASS 表示审计完成，不表示原型通过同一步骤语义验收。

## 口径与可追溯性

“首次入池”指 `candidate.generate` 首次插入诊断 Proposal，**不是**最终状态。14 个跨 GT 双成员 Proposal 最早来自 pair 穷举；6 个多成员 Proposal 来自既有 context/binding bucket。该顺序通过冻结代码循环顺序和已输出成员键静态重建，未执行 generator；原始 ledger 的来源是排序后的集合，不能当作时间顺序。池中还故意存在 NO_RELATION pair，入池本身不声称同一步骤。

“保留”指 `grouping.evaluate` 赋予 CANDIDATE。`bounded_description` 的 `has_direct`、`any(request)`、`any(execution)`、`any(SSH file)`、`any(port 22)` 可能来自不同成员；最后只要求 finite、多成员、E1/E2/E3。通用 Proposal 的 `identity_kind=None` 直接跳过 activity identity 冲突检查；逐 pair 检查存在不等于共同目的校验；P1 不完整被写入未决问题。支持告警列表包含全部成员告警，也不等于这些告警都有 membership witness。

首次入池位置：`{audit.locations['pair']}`；最终状态位置：`{audit.locations['retention']}`；identity 跳过位置：`{audit.locations['identity_skip']}`；正证据分区位置：`{audit.locations['positive_partition']}`。完整路径在 admission/retention 两份 JSON 和逐 Candidate JSONL。

ADMISSION_CONTAMINATION=0、RETENTION_CONTAMINATION=20、BOTH=0 使用互斥的“诊断池/状态”口径。若把 Admission 一词理解为 same-step eligibility，则下文 OVER_ADMISSION 计数描述的正是资格门过宽；它们不表示首次入池的独立错误。仍需重设计 eligibility 语义，不能只改枚举规模。

这也不等于“Candidate 缺少 P1 就违反契约”。冻结契约第 6 节明确允许可核实有限假设以 E1/E2/E3 保留为 CANDIDATE；当前实现遵循该状态框架。本轮发现的是 finite hypothesis 的可观察语义不足，属于语义校准缺口，不是擅自要求所有候选满足 P1。反事实严格边界场景也不是现有契约的强制条件。

## Q1：20 个跨 GT Candidate 怎么产生？

15 个由 accepted 内部关系触发，包括 10 个双成员和 5 个多成员；5 个由 shared flow + 每成员 Web 告警外形触发，包括 4 个双成员和 1 个五成员。共 6 个多成员扩展污染；这是取已有 bucket 的全体成员，不是运行了传递 union。一个内部关系或共同上下文被用于解释整组，而没有逐成员的同一步骤目的证明。

## Q2：Admission 还是 Retention？

主要在 Retention。129 Proposal 中 pair 穷举有 {enum['PAIR_ENUMERATION_PROPOSALS']} 个（15 choose 2），其余是 singleton 与带 identity-kind 的 bucket 等。首次诊断检索可以宽，CANDIDATE 资格必须具有成员语义。context bucket={enum['CONTEXT_BUCKET_PROPOSALS']}、relation-origin={enum['RELATION_DERIVED_PROPOSALS']}（含 NO_RELATION）、accepted relation-origin={enum['ACCEPTED_RELATION_DERIVED_PROPOSALS']}、多成员 Proposal={enum['MULTI_STAGE_EXPANSION_PROPOSALS']}。来源可重叠；来源全集统计与互斥 first-source 统计分别保存在 enumeration_source_analysis.json。

## Q3：关系证据被如何误用？

AUTH_ESTABLISH_USE 是认证→后续使用；CONNECTION_ESTABLISH_ACCEPT 是源端连接→远端接收；OBJECT_HANDOFF 是对象生产→后续请求消费。它们能支持过程联系，不能自动支持同一个 Step。SAME_TRUSTED_CONNECTION/SAME_PROCESS_INSTANCE 是关联；parent-child 是真实 ancestry，但高层活动边界通常仍不确定。12 条 accepted relation 全部逐条审计，判断依赖原生类型、角色、scope、witness 和覆盖，先于 GT 标签；2 同 GT/10 跨 GT 不代表⑧错误。15 个跨 GT Candidate 使用了“有效关系足以提供有限同一步骤描述”的路径，其中既有明确 progression，也有语义仍不确定的 lineage，不能把这两者混为已知跨步骤。

RELATION_EVIDENCE 回答两个动作有没有关系；MEMBERSHIP_EVIDENCE 回答为何属于同一有边界的高层活动。这里仅为审计术语，没有修改契约。

## Q4：两个正确候选存在可泛化的可观察差异吗？

存在局部原生差异，**尚无经过验证的安全高层边界差异**。S04 全部 10 条成员告警具有共同 scoped request，原生 ApplicationRequest 的 parent 与 child 角色绑定完整，可作为有条件的 SAME_STEP 候选线索；但同一 request 还覆盖上传动作，且相同 child process instance 延续到凭据文件操作。S05 同路径、部分同文件哈希、lineage 与 `ssh -i` 参数线索强于纯 session 共现；但 NetworkConnection 不是已证明的凭据消费，路径/哈希/参数也不证明实际认证使用或共同目的。

`CURRENT_FEATURES_CANNOT_DISTINGUISH_SAFE_PARENT_CHILD_SAME_STEP` 指不能安全确定高层边界；不表示字段完全相同，也不否认局部候选兼容线索。最终两项 DISTINGUISHABLE=false 均使用“安全、可泛化高层 membership”口径。S04 的条件证据列为 SAME_STEP_EVIDENCE，不能据此宣称已确认或可靠 closed boundary；S05 保留 AMBIGUOUS。

## Q5：是否无法安全自动建 Candidate？

当前输入和证据模型不足以验证安全自动资格；应允许 UNRESOLVED/人工复核。不能据一个固定数据集推断所有未来数据都不可观测，也不能把 GT 正确等同于可靠机制。六个 S02 纯子集均是 GENERIC_SHARED_CONTEXT，伴随 ENUMERATION_ARTIFACT；同 flow/Web 机制也产生 5 个混合候选，六个纯 pair 不能当作六次完整 episode 还原。

## Q6：最小应改哪个抽象层？

先定义 **MEMBERSHIP_EVIDENCE_MODEL + STEP_BOUNDARY_MODEL**：共同活动是什么、哪个原生角色绑定支持它、每个成员如何覆盖、何时应保留不确定。随后才可据此设计 admission/retention 及 whole-group expansion。改标签分类、加同 Chain 限制或提高阈值没有提供缺失的目的证据。请求→执行、凭据对象→使用均不属于当前 P1 的自动确认规则；P1 仍是完整 REQUEST_RESPONSE 且本数据 claim=0。

## Q7：是否支持继续实现 Prototype v2？

`PROTOTYPE_V2_JUSTIFIED=false`。支持继续做只读的可观察边界定义和证据采集研究；尚不足以开始靠增加规则实现自动分组 v2。S04 有局部候选线索，但没有可靠的闭合 Step 边界；S05 实际对象使用绑定缺失。下一步为 DEFINE_OBSERVABLE_STEP_BOUNDARY，必须先取得独立且更多样的证据与留出验证。

## 正向证据全量重分类

共 {len(audit.semantic_occurrences)} 个 positive_evidence **出现项**，每项恰归一类：{json.dumps(dict(categories), ensure_ascii=False)}。`evidence_semantic_classification.json` 保存每项 candidate_id、ledger pointer、ref、parent claims、类别和理由。trace validation/resolution 只说明可追溯/有效，继承所属 claim 的语义而不新增 membership；多用途 trace 保留 AMBIGUOUS。S04 的 SAME_STEP 项只在联合 request/parent-child/full-selected-coverage 条件下成立，并非单项足够，也非边界已证明。未用 GT 来决定证据类别。

## 风险暴露与真实触发

独立评估暴露人数复核：lineage=8、session=10、flow=6、host=12、account=5、authentication lifecycle=1、incoming SSH=2、outbound connection=1。8 个跨 GT 候选具有可使描述成立的有效 lineage witness，但只有 4 个仅以 lineage 为有效关系家族，另 4 个同时具有可替代的 accepted process 关系；不能把全部 8 个称为 lineage 的必要因果影响。最终 PROCESS_LINEAGE_OVER_ADMISSION_COUNT=8 使用“参与资格的 witness”口径，counterfactual 的 lineage-only=4 使用“唯一有效关系家族”口径。flow/Web 直接资格有 5 个。host/account/session 没有独立保留分支，session-only 与 host/account-only 反事实删除数均为 0。Session bucket 仍可能首次检索多成员组，但不能把 10 个 session 暴露都算成 session 因果资格。所有场景逐项列在 risk_family_analysis.json。

## 只读反事实集合分析

所有场景只在冻结 ledger 做集合减法，未重跑任何修改版原型，未选择“GT 指标最好”的过滤器。`only` 指实际资格 binding 家族，描述标签和上下文暴露不算独立 membership 证明；S04 的独立联合候选线索排除在 relation-only/lineage-only 之外。没有模拟删除证据后备用分支如何运行。require_membership_evidence 是宽松的联合候选线索敏感性场景；另附“可靠 membership”严格口径，后者会删除全部 28 个。

| 场景 | 删除精确正例 | 删除纯子集 | 删除跨 GT | 保留跨 GT |
|---|---:|---:|---:|---:|
'''
    for s in counter['scenarios']:
        rc, kc = s['removed_counts'], s['kept_counts']
        text += f"| {s['name']} | {rc[TRUTH[0]]} | {rc[TRUTH[1]]} | {rc[TRUTH[2]]} | {kc[TRUTH[2]]} |\n"
    text += '\n删除 relation/lineage 也会损失精确正例；只保留局部 request 线索会损失 S05 和全部 6 个纯子集。边界严格过滤会删掉所有已知正例。这些是风险描述，不是上线建议。\n\n## 20/20 跨 GT 逐项索引\n\n| Candidate | 成员数 | GT（仅审计） | 首次入池 | 保留描述 | 主因 |\n|---|---:|---|---|---|---|\n'
    for r in mixed:
        text += f"| {r['candidate_id']} | {len(r['member_stage_ids'])} | {','.join(r['gt_stage_ids'])} | {r['FIRST_ADMISSION_RULE']} | {r['semantic_labels'][0]} | {r['PRIMARY_ROOT_CAUSE']} |\n"
    text += '\n每项的完整 member/chain/claim/observation/context 与代码位置见 candidate_contamination_audit.jsonl。多成员组主因 H、Web pair 主因 D、关系 pair 主因 A；共同抽象根因 K，次因 I/G 等。主因互斥，次因可重叠，不把 co-occurrence 当因果。\n\n## Relation / Membership 矩阵\n\n| Evidence | 有关系？ | Same-Step 候选支持 | 单独足够确认？ |\n|---|---|---|---|\n'
    for m in relation_matrix()['rows']:
        text += f"| {m['evidence']} | {m['proves_relation']} | {m['supports_same_step_candidate']} | 否 |\n"
    text += '\n完整理由与冻结 P1 约束在 relation_vs_membership_matrix.json。审计结论受单一封存数据集、缺少可验证的高层目的标签/对象使用证明限制；本轮没有宣称筛选器具有样本外安全性。\n\n## 最终状态\n\n```text\n'
    for key, value in result.items():
        rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, (bool, list)) else str(value)
        text += f'{key}={rendered}\n'
    text += '```\n'
    (output / 'FINAL_AUDIT_REPORT.md').write_text(text, encoding='utf-8')


def run(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    if not output.is_relative_to(root / 'outputs'):
        raise ValueError('Audit artifacts must stay within workspace outputs')
    output.mkdir(parents=True, exist_ok=True)
    audit = Audit(root)  # SHA check occurs before population analysis.
    verification = audit.verify_inputs()
    dump(output / 'input_verification.json', verification)
    rows = audit.rows()
    (output / 'candidate_contamination_audit.jsonl').write_text(
        ''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in rows), encoding='utf-8')
    dump(output / 'candidate_admission_paths.json', dict(mode='STATIC_SOURCE_ORDER_PROVENANCE_RECONSTRUCTION',
        prototype_executed=False, sorted_reason_set_is_not_chronology=True,
        rows=[dict(candidate_id=r['candidate_id'], FIRST_CANDIDATE_ADMISSION_POINT=audit.origins[r['candidate_id']][0],
                   all_source_paths=audit.origins[r['candidate_id']]) for r in rows]))
    dump(output / 'candidate_retention_paths.json', dict(rows=[r['retention_path'] for r in rows],
        locus='RETENTION_DOMINANT', population='All 28 CANDIDATE'))
    for record in audit.relation_semantics:
        gt = audit.truth[record['candidate_id']]
        record['offline_gt_stage_ids'] = gt['gt_stage_ids']
        record['offline_same_gt'] = len(gt['gt_stage_ids']) == 1
    dump(output / 'relation_candidate_semantics.json', dict(rows=audit.relation_semantics,
        accepted_count=len(audit.relation_semantics), classification_counts=dict(Counter(r['classification'] for r in audit.relation_semantics)),
        gt_used_for_semantic_judgment=False, cross_gt_relation_does_not_imply_stage8_error=True))
    counts = Counter(x['classification'] for x in audit.semantic_occurrences)
    assert sum(counts.values()) == sum(len(x['positive_evidence']) for x in audit.candidates)
    dump(output / 'evidence_semantic_classification.json', dict(categories=list(CATEGORIES),
        occurrence_count=len(audit.semantic_occurrences), category_counts={c: counts[c] for c in CATEGORIES},
        unique_occurrence_ids=len({x['occurrence_id'] for x in audit.semantic_occurrences}),
        classification_scope='Candidate-scoped semantics, not validity or GT membership. SAME_STEP may be a conditional composite clue, never standalone confirmation.',
        classification_uses_gt=False, occurrences=audit.semantic_occurrences))
    dump(output / 'cross_gt_candidate_root_causes.json', dict(
        rows=[{k: r[k] for k in ['candidate_id', 'member_stage_ids', 'gt_stage_ids', 'PRIMARY_ROOT_CAUSE',
            'SECONDARY_ROOT_CAUSES', 'FIRST_CANDIDATE_ADMISSION_POINT', 'RETENTION_EVIDENCE', 'audit_conclusion']} for r in rows if r['gt_classification'] == 'CROSS_GT_MIXED'],
        primary_root_cause_counts=dict(Counter(r['PRIMARY_ROOT_CAUSE'] for r in rows if r['PRIMARY_ROOT_CAUSE'])),
        relation_semantic_family_candidate_counts={family: sum(
            any(q['classification'] == family for q in r['relation_evidence'])
            for r in rows if r['gt_classification'] == 'CROSS_GT_MIXED')
            for family in ['CROSS_STEP_PROGRESSION', 'ASSOCIATION_ONLY', 'UNDETERMINED', 'SAME_STEP_COMPATIBLE']},
        abstract_primary_root_cause=ROOTS['K'], count_scope='Primary roots partition 20; secondary roots overlap. Labels OVER_ADMISSION refer to semantic eligibility, not diagnostic pool entry.'))
    dump(output / 'positive_candidate_controls.json', audit.controls(rows))
    dump(output / 'pure_subset_analysis.json', audit.pure_subsets(rows))
    enum = audit.enumeration()
    dump(output / 'enumeration_source_analysis.json', enum)
    dump(output / 'relation_vs_membership_matrix.json', relation_matrix())
    counter = audit.counterfactuals(rows)
    dump(output / 'counterfactual_filter_analysis.json', counter)
    dump(output / 'risk_family_analysis.json', dict(rows=audit.risk_analysis(rows),
        exposure_counts_are_not_causal_counts=True, SESSION_IS_CONTEXT_NOT_STEP_BOUNDARY=True))
    dump(output / 'prototype_v2_design_constraints.json', design_constraints())
    immutable = integrity(output)
    result = task_result(rows, immutable)
    dump(output / 'task_result.json', result)
    dump(output / 'metric_definitions.json', dict(
        ADMISSION_CONTAMINATION_COUNT='Erroneous membership assertion at diagnostic proposal-pool insertion. Pool entry asserts no membership; zero.',
        RETENTION_CONTAMINATION_COUNT='Mixed-GT diagnostic proposals converted to CANDIDATE without reliable membership semantics; 20.',
        BOTH_CONTAMINATION_COUNT='Intersection of the previous two loci under the stated strict pool/status distinction; zero.',
        RELATION_EVIDENCE_MISUSED_COUNT='Mixed candidates whose valid accepted-relation path suffices for a finite description without whole-candidate membership support. Includes definite progression, association and undetermined ancestry; does not label all of them definitely CROSS_STEP from native semantics.',
        SHARED_CONTEXT_OVER_ADMISSION_COUNT='Mixed candidates whose binding basis is shared flow plus Web shape. Context exposure alone is not counted.',
        PROCESS_LINEAGE_OVER_ADMISSION_COUNT='Mixed candidates with a valid, qualifying parent-child witness: 8. Four also have alternative valid process-instance relations; only 4 have lineage as their sole qualifying relation family.',
        SESSION_OVER_ADMISSION_COUNT='Mixed candidates retained by a session-only predicate: zero. Session bucket retrieval is recorded separately.',
        FLOW_OVER_ADMISSION_COUNT='Mixed candidates retained by the explicit flow+Web branch: 5, versus 6 flow exposures.',
        SEMANTIC_OVER_ADMISSION_COUNT='Mixed candidates with Web detector shape in the qualifying flow+Web predicate: 5. Semantic-label-only retention count is zero.',
        GROUP_EXPANSION_CONTAMINATION_COUNT='Mixed CANDIDATE with >2 members: 6. Existing context/binding buckets, not transitive union.',
        PURE_CANDIDATES_AUDITED='2 EXACT_GT_STEP + 6 PURE_GT_SUBSET controls; 8 total.',
        SAFE_GENERALIZABLE_DIFFERENCE_FOUND='A validated high-level membership/boundary distinction. False does not deny local feature differences or the provisional scoped-request composite clue.',
        GT_S04_DISTINGUISHABLE_WITH_OBSERVABLE_EVIDENCE='Same safe high-level boundary distinction scope; local raw differences exist but safe generalization is not established.',
        GT_S05_DISTINGUISHABLE_WITH_OBSERVABLE_EVIDENCE='Same safe high-level boundary distinction scope; actual object consumption and purpose binding are not proved.',
        PROTOTYPE_V2_JUSTIFIED='Whether current evidence justifies implementation of automatic v2 membership. False; read-only boundary-definition/evidence research remains warranted.',
        TASK_RESULT='Completion and integrity of the audit, not semantic acceptance of v1.',
        overlap='Evidence-family counts overlap; first-source proposal counts and primary-root counts partition their populations.'))
    report(audit, rows, enum, counter, result, output)
    dump(output / 'audit_validation.json', dict(candidate_count=len(rows),
        cross_gt_candidates_audited=sum(r['gt_classification'] == 'CROSS_GT_MIXED' for r in rows),
        accepted_relations_audited=len(audit.relation_semantics),
        positive_evidence_occurrences=len(audit.semantic_occurrences),
        unclassified_evidence_occurrences=0, multiple_classifications_per_occurrence=0,
        protected_files_unchanged=immutable, prototype_or_pipeline_executed=False,
        gt_independent_native_semantics=True, all_required_artifacts_written=True))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--output', default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        run(args.root, Path(args.root) / args.output)
    except ValueError as exc:
        if str(exc).startswith('BLOCKED:'):
            destination = Path(args.root) / args.output
            destination.mkdir(parents=True, exist_ok=True)
            dump(destination / 'task_result.json', dict(TASK_RESULT='BLOCKED',
                AUDIT_MODE='CANDIDATE_CONTAMINATION', PROTOTYPE_OUTPUT_SHA_VERIFIED=False, reason=str(exc)))
        raise

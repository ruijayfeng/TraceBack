#!/usr/bin/env node
/**
 * T14 — Impeccable design-detector baseline / ratchet (source scan only).
 *
 * The project ships the Impeccable skill under `TraceBack/.dsh/skills/impeccable/`.
 * Its bundled detector is a self-contained binary (no Node runtime / no service
 * needed for source scans), invoked as:
 *
 *   .dsh/skills/impeccable/scripts/impeccable detect --json frontend/src
 *
 * This script pins a reviewed baseline of the current findings to
 * `design-libs/baseline/detector/source-baseline.json` and adds a ratchet:
 *
 *   default          scan, print summary + drift, write the baseline if it is
 *                    missing; always exits 0 (informational, for developers)
 *   --update         scan and (re)write the baseline file
 *   --check          scan, compare with the baseline and exit 1 only when a NEW
 *                    P0-level finding appears. Historical debt (all findings
 *                    already recorded in the baseline) and new non-P0 findings are
 *                    printed but do not fail the build.
 *
 * P0 definition (stored in the baseline so it is reviewable):
 *   a finding is P0 when the detector reports `severity: "error"` (its blocking
 *   tier: script-error / content-hidden-at-rest), or when its rule id is listed
 *   in `p0.extraRules`. Warnings/advisories are historical quality debt here and
 *   never gate CI by themselves.
 *
 * Fingerprints deliberately exclude line numbers: `rule|relative-file|snippet`.
 * Editing unrelated lines in `app.css` therefore does not make old debt "new".
 *
 * URL scans are NOT part of this ratchet: they need a running page/browser and
 * are covered by the Playwright visual/a11y suites (T12/T13) instead.
 *
 * Usage (from frontend/):
 *   npm run detect:ui                       # informational scan + drift summary
 *   npm run detect:ui -- --update           # refresh the baseline
 *   npm run detect:ui:check                 # CI ratchet (exit 1 on new P0 only)
 *   node ../scripts/ui_detector_ratchet.mjs --check --baseline /tmp/x.json
 */

import {spawnSync} from 'node:child_process';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, isAbsolute, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const SKILL_DIR = resolve(REPO_ROOT, '.dsh/skills/impeccable');
const DETECTOR = resolve(SKILL_DIR, 'scripts/impeccable');
const DEFAULT_BASELINE = resolve(REPO_ROOT, '..', 'design-libs/baseline/detector/source-baseline.json');
const DEFAULT_TARGETS = ['frontend/src'];
const DEFAULT_P0_RULES = ['script-error', 'content-hidden-at-rest'];
const DEFAULT_P0_SEVERITIES = ['error'];

function parseArgs(argv) {
  const options = {mode: 'report', update: false, check: false, json: false, baseline: DEFAULT_BASELINE, targets: [...DEFAULT_TARGETS]};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--update') options.update = true;
    else if (arg === '--check') options.check = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--baseline') options.baseline = resolve(argv[++i] ?? '');
    else if (arg === '--target') options.targets.push(argv[++i] ?? '');
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: ui_detector_ratchet.mjs [--check | --update] [--json] [--baseline <path>] [--target <path>]');
      process.exit(0);
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  if (options.update && options.check) throw new Error('Use either --update or --check, not both.');
  options.mode = options.update ? 'update' : options.check ? 'check' : 'report';
  return options;
}

function readFileIfExists(file) {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function toolVersions() {
  const skillVersion = (readFileIfExists(resolve(SKILL_DIR, 'SKILL.md')) ?? '').match(/^version:\s*(\S+)/m)?.[1] ?? 'unknown';
  const engineVersion = (readFileIfExists(resolve(SKILL_DIR, 'scripts/VERSION')) ?? '').trim() || 'unknown';
  return {skillVersion, engineVersion};
}

function relativeToRepo(file) {
  const absolute = resolve(file);
  const rel = isAbsolute(file) ? relative(REPO_ROOT, absolute) : file;
  return rel.split(sep).join('/');
}

function normalizeFinding(raw) {
  const rule = String(raw.antipattern ?? raw.rule ?? 'unknown');
  const file = relativeToRepo(String(raw.file ?? ''));
  const snippet = String(raw.snippet ?? '').trim().replace(/\s+/g, ' ').slice(0, 300);
  return {
    rule,
    name: raw.name ?? rule,
    severity: raw.severity ?? 'unknown',
    category: raw.category ?? 'unknown',
    file,
    line: Number(raw.line ?? 0),
    snippet,
    fingerprint: `${rule}|${file}|${snippet}`,
  };
}

function runDetector(targets) {
  if (!existsSync(DETECTOR)) throw new Error(`Impeccable detector launcher not found: ${DETECTOR}`);
  const result = spawnSync(DETECTOR, ['detect', '--json', ...targets], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    env: process.env,
  });
  if (result.error) throw new Error(`detector could not start: ${result.error.message}`);
  // Exit codes documented by the detector: 0 = clean, 2 = primary findings, 1 = target failure.
  if (result.status !== 0 && result.status !== 2) {
    throw new Error(`detector failed (exit ${result.status}): ${(result.stderr || '').trim().slice(0, 2000)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout || '[]');
  } catch {
    throw new Error(`detector did not return JSON on stdout. stderr: ${(result.stderr || '').trim().slice(0, 1000)}`);
  }
  if (!Array.isArray(parsed)) throw new Error('detector JSON output was not an array');
  return parsed.map(normalizeFinding);
}

/** Collapse duplicate fingerprints (same rule/file/snippet) into one entry with an occurrence count. */
function collapse(findings) {
  const byFingerprint = new Map();
  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (existing) existing.occurrences += 1;
    else byFingerprint.set(finding.fingerprint, {...finding, occurrences: 1});
  }
  return [...byFingerprint.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}

function summarize(findings) {
  const bySeverity = {};
  const byRule = {};
  const byFile = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    byRule[finding.rule] = (byRule[finding.rule] ?? 0) + 1;
    byFile[finding.file] = (byFile[finding.file] ?? 0) + 1;
  }
  return {total: findings.length, bySeverity, byRule, byFile};
}

function loadPolicy(baseline) {
  const p0 = baseline?.p0 ?? {};
  return {
    severities: Array.isArray(p0.severities) && p0.severities.length ? p0.severities : DEFAULT_P0_SEVERITIES,
    extraRules: Array.isArray(p0.extraRules) ? p0.extraRules : DEFAULT_P0_RULES,
  };
}

function isP0(finding, policy) {
  return policy.severities.includes(finding.severity) || policy.extraRules.includes(finding.rule);
}

function buildBaseline(findings, targets) {
  const versions = toolVersions();
  return {
    schemaVersion: 1,
    kind: 'impeccable-design-detector-source-baseline',
    generatedAt: new Date().toISOString(),
    tool: {name: 'impeccable', ...versions, command: '.dsh/skills/impeccable/scripts/impeccable detect --json ' + targets.join(' ')},
    targets,
    scan: {
      mode: 'source',
      repoRoot: REPO_ROOT,
      notes: 'Source scan only. URL scans need a browser/page and are covered by Playwright (T12/T13). Fingerprints are rule|file|snippet (line numbers excluded) so edits elsewhere do not create fake new debt.',
    },
    p0: {
      definition: "P0 = detector severity 'error' (blocking tier) or rule id in extraRules. Historical warnings/advisories never fail the ratchet.",
      severities: DEFAULT_P0_SEVERITIES,
      extraRules: DEFAULT_P0_RULES,
    },
    summary: summarize(findings),
    findings,
  };
}

function readBaseline(file) {
  const text = readFileIfExists(file);
  if (text === null) return null;
  try {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed.findings)) throw new Error('baseline has no findings array');
    return parsed;
  } catch (error) {
    throw new Error(`cannot read baseline ${file}: ${error.message}`);
  }
}

function writeBaseline(file, baseline) {
  mkdirSync(dirname(file), {recursive: true});
  writeFileSync(file, JSON.stringify(baseline, null, 2) + '\n');
}

function printFindings(findings, label) {
  if (!findings.length) return;
  console.log(`${label} (${findings.length}):`);
  for (const finding of findings) {
    console.log(`  [${finding.severity}] ${finding.rule} — ${finding.file}:${finding.line} (${finding.occurrences}x) ${finding.snippet.slice(0, 90)}`);
  }
}

function run(options) {
  const currentRaw = runDetector(options.targets);
  const findings = collapse(currentRaw);
  const currentSummary = summarize(findings);
  const baseline = readBaseline(options.baseline);
  const policy = loadPolicy(baseline);
  const versionInfo = toolVersions();

  const results = {current: {findings, summary: currentSummary, rawCount: currentRaw.length}, baselinePath: options.baseline, baseline: null, drift: null, policy};
  let exitCode = 0;

  const writeAndReport = (reason) => {
    const created = buildBaseline(findings, options.targets);
    writeBaseline(options.baseline, created);
    results.baseline = created;
    console.log(`Baseline ${reason}: ${options.baseline}`);
    console.log(`  ${findings.length} unique findings — ${JSON.stringify(currentSummary.bySeverity)}`);
    if (options.mode === 'update') console.log('Baseline updated.');
    else console.log('Run `npm run detect:ui:check` to use it as a ratchet.');
    return created;
  };

  if (!baseline) {
    console.log(`Detector: impeccable ${versionInfo.skillVersion} / engine ${versionInfo.engineVersion}`);
    console.log(`Scan targets: ${options.targets.join(', ')} (source scan; ${currentRaw.length} raw findings, ${findings.length} unique)`);
    console.log(`No baseline found at ${options.baseline}`);
    writeAndReport('generated');
    if (options.check) console.log('NOTE: --check on a missing baseline records current debt instead of failing; commit/review the baseline.');
    return {exitCode: 0, results};
  }

  const baselineKeys = new Map(baseline.findings.map(finding => [finding.fingerprint, finding]));
  const currentKeys = new Map(findings.map(finding => [finding.fingerprint, finding]));
  const added = findings.filter(finding => !baselineKeys.has(finding.fingerprint));
  const resolved = baseline.findings.filter(finding => !currentKeys.has(finding.fingerprint));
  const newP0 = added.filter(finding => isP0(finding, policy));
  const resolvedP0 = resolved.filter(finding => isP0(finding, policy));
  const historical = findings.filter(finding => baselineKeys.has(finding.fingerprint));

  results.baseline = baseline;
  results.drift = {added, resolved, newP0, resolvedP0, historical};

  console.log(`Detector: impeccable ${versionInfo.skillVersion} / engine ${versionInfo.engineVersion}`);
  console.log(`Scan targets: ${options.targets.join(', ')} (source scan; ${currentRaw.length} raw findings, ${findings.length} unique)`);
  console.log(`Current: ${findings.length} findings — ${JSON.stringify(currentSummary.bySeverity)}`);
  console.log(`Baseline: ${baseline.findings.length} findings (${baseline.generatedAt ?? 'unknown date'}); historical debt in current scan: ${historical.length}`);
  console.log(`P0 policy: severities=${JSON.stringify(policy.severities)} extraRules=${JSON.stringify(policy.extraRules)}`);
  printFindings(added, 'NEW findings (not in baseline)');
  printFindings(resolved, 'RESOLVED findings (baseline debt no longer present)');
  printFindings(newP0, 'NEW P0 findings (gate)');
  if (resolvedP0.length) console.log(`Resolved P0 findings: ${resolvedP0.length} (good — refresh the baseline when convenient)`);

  if (options.update) {
    const created = writeAndReport('updated');
    results.baseline = created;
    console.log('Baseline updated.');
    return {exitCode: 0, results};
  }

  if (newP0.length) {
    console.log(`RESULT: FAIL — ${newP0.length} new P0 finding(s). Fix them or record an explicit, reviewed exception in .impeccable config.`);
    exitCode = options.check ? 1 : 0;
    if (!options.check) console.log('(report mode: not failing; use --check for the CI gate)');
  } else if (added.length) {
    console.log(`RESULT: PASS — ${added.length} new non-P0 finding(s) are informational only.`);
  } else if (resolved.length) {
    console.log(`RESULT: PASS — no new findings; ${resolved.length} historical finding(s) resolved (baseline can be refreshed).`);
  } else {
    console.log('RESULT: PASS — no drift against the source baseline.');
  }
  return {exitCode, results};
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    const {exitCode, results} = run(options);
    if (options.json) console.log(JSON.stringify({exitCode, ...results, findings: results.current.findings}, null, 2));
    process.exit(exitCode);
  } catch (error) {
    console.error(`ui_detector_ratchet: ${error.message}`);
    process.exit(2);
  }
}

main();

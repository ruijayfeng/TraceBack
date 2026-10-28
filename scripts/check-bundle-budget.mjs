#!/usr/bin/env node
/**
 * T90 — bundle budget gate. Measures the built entry assets (gzip) so UI work
 * cannot silently grow the initial payload. Budgets are intentionally roomy for
 * the coss/Base UI component runtime, but tight enough to catch accidental
 * full-library imports (e.g. `import * as icons from "lucide-react"`).
 *
 *   node scripts/check-bundle-budget.mjs [--json]
 *
 * Run after `npm run build` (expects frontend/dist/assets).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const assetsDir = join(repo, 'frontend', 'dist', 'assets');
const BUDGETS = { js: 160 * 1024, css: 20 * 1024 };

let files;
try {
  files = readdirSync(assetsDir);
} catch {
  console.error(`[bundle-budget] missing ${assetsDir}; run "npm run build" first.`);
  process.exit(1);
}
const measure = (pattern) => files.filter(name => pattern.test(name)).map(name => {
  const raw = readFileSync(join(assetsDir, name));
  return { name, raw: raw.length, gzip: gzipSync(raw, { level: 9 }).length };
});
const js = measure(/^index-.*\.js$/);
const css = measure(/^index-.*\.css$/);
const sum = (items, key) => items.reduce((total, item) => total + item[key], 0);
const rows = [...js, ...css];
const jsGzip = sum(js, 'gzip'), cssGzip = sum(css, 'gzip');
const report = { budgets: BUDGETS, js, css, jsGzip, cssGzip, pass: jsGzip <= BUDGETS.js && cssGzip <= BUDGETS.css };
if (process.argv.includes('--json')) {
  console.log(JSON.stringify(report, null, 2));
} else {
  for (const row of rows) console.log(`  ${row.name}  raw ${(row.raw / 1024).toFixed(1)} KB · gzip ${(row.gzip / 1024).toFixed(2)} KB`);
  console.log(`[bundle-budget] JS gzip ${(jsGzip / 1024).toFixed(2)} / ${(BUDGETS.js / 1024).toFixed(0)} KB · CSS gzip ${(cssGzip / 1024).toFixed(2)} / ${(BUDGETS.css / 1024).toFixed(0)} KB`);
  console.log(report.pass ? '[bundle-budget] PASS' : '[bundle-budget] FAIL — initial payload over budget');
}
process.exit(report.pass ? 0 : 1);

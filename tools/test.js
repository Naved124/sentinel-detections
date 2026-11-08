#!/usr/bin/env node
// Runs each rule's test cases.
//
// For every case the rule's tables are replaced with `let` datatables holding the case's rows,
// timestamps are placed relative to now, and the query is run on a Kusto engine (the free Kusto
// emulator in Docker, or any cluster you can reach without auth). The result is compared with the
// case's `expect` block.
//
//   npm test                    run against KUSTO_URL (default http://localhost:8080)
//   npm test -- --offline       only check that every generated test query is valid KQL
//   npm test -- SIGNIN-002      run one rule
'use strict';

const { loadRules, loadSchemas, analyze, buildTestQuery } = require('./lib');

const KUSTO_URL = (process.env.KUSTO_URL || 'http://localhost:8080').replace(/\/$/, '');
const KUSTO_DB = process.env.KUSTO_DB || 'NetDefaultDB';

async function runQuery(csl) {
  const response = await fetch(`${KUSTO_URL}/v1/rest/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8', Accept: 'application/json' },
    body: JSON.stringify({ db: KUSTO_DB, csl }),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`Kusto returned HTTP ${response.status}: ${text.slice(0, 600)}`);
  const table = JSON.parse(text).Tables[0];
  const names = table.Columns.map((c) => c.ColumnName);
  return table.Rows.map((row) => Object.fromEntries(row.map((value, i) => [names[i], value])));
}

function same(actual, expected) {
  if (typeof expected === 'number') return Number(actual) === expected;
  if (typeof expected === 'boolean') return actual === expected || String(actual).toLowerCase() === String(expected);
  if (Array.isArray(expected) || (expected && typeof expected === 'object')) {
    const parsed = typeof actual === 'string' ? safeJson(actual) : actual;
    return JSON.stringify(sortDeep(parsed)) === JSON.stringify(sortDeep(expected));
  }
  return String(actual) === String(expected);
}

function safeJson(text) {
  try { return JSON.parse(text); } catch { return text; }
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortDeep(value[k])]));
  }
  return value;
}

/** Check rows against expect: {rows: N, match: {col: value}} (match applies to every returned row). */
function check(rows, expect) {
  const problems = [];
  if (rows.length !== expect.rows) problems.push(`expected ${expect.rows} row(s), got ${rows.length}`);
  for (const [column, value] of Object.entries(expect.match || {})) {
    for (const [i, row] of rows.entries()) {
      if (!(column in row)) problems.push(`row ${i}: no column '${column}'`);
      else if (!same(row[column], value)) {
        problems.push(`row ${i}: ${column} = ${JSON.stringify(row[column])}, expected ${JSON.stringify(value)}`);
      }
    }
  }
  return problems;
}

async function waitForEngine() {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { await runQuery('print ok = 1'); return; } catch (err) {
      if (attempt === 2) throw err;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const offline = args.includes('--offline');
  const only = args.filter((a) => !a.startsWith('--'));
  const schemas = loadSchemas();
  const rules = loadRules().filter((r) => only.length === 0 || only.includes(r.ruleId));
  if (rules.length === 0) { console.error('no matching rules'); process.exit(1); }

  if (!offline) {
    try { await waitForEngine(); } catch (err) {
      console.error(`Cannot reach a Kusto engine at ${KUSTO_URL}: ${err.message}\n` +
        'Start the emulator (see README) or run `npm run test:offline`.');
      process.exit(1);
    }
  }

  let passed = 0;
  let failed = 0;
  for (const rule of rules) {
    console.log(`${rule.ruleId}  ${rule.name}`);
    for (const testCase of rule.tests || []) {
      let problems = [];
      try {
        const query = buildTestQuery(rule, testCase, schemas);
        const { errors } = analyze(query, schemas, { withTables: false });
        problems = errors.map((e) => `KQL line ${e.line}:${e.column}: ${e.message}`);
        if (!problems.length && !offline) problems = check(await runQuery(query), testCase.expect);
      } catch (err) {
        problems = [err.message];
      }
      if (problems.length) {
        failed++;
        console.log(`  ✗ ${testCase.name}`);
        for (const p of problems) console.log(`      ${p}`);
      } else {
        passed++;
        console.log(`  ✓ ${testCase.name}`);
      }
    }
  }
  const mode = offline ? ' (offline: KQL validity only, results not checked)' : '';
  console.log(`\n${passed} passed, ${failed} failed${mode}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main();
module.exports = { check, same };

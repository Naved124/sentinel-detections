// Shared helpers: loading rules and schemas, the KQL analyzer, and test-data generation.
'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');

const Kusto = globalThis.Kusto;
const K = Kusto.Language;
const S = K.Symbols;

const ROOT = path.resolve(__dirname, '..');
const RULES_DIR = path.join(ROOT, 'rules');

function loadSchemas() {
  return yaml.load(fs.readFileSync(path.join(ROOT, 'schemas', 'tables.yaml'), 'utf8'));
}

function loadRules() {
  return fs.readdirSync(RULES_DIR)
    .filter((f) => f.endsWith('.yaml'))
    .sort()
    .map((file) => ({ file, ...yaml.load(fs.readFileSync(path.join(RULES_DIR, file), 'utf8')) }));
}

// ---------------------------------------------------------------- analyzer

function schemaString(columns) {
  return '(' + Object.entries(columns).map(([name, type]) => `['${name}']:${type}`).join(', ') + ')';
}

let cachedState = null;
function globalState(schemas) {
  if (cachedState) return cachedState;
  const tables = Object.entries(schemas).map(([name, cols]) => S.TableSymbol.From(schemaString(cols)).WithName(name));
  const db = new S.DatabaseSymbol.ctor('Sentinel', tables);
  cachedState = K.GlobalState.Default.WithDatabase(db);
  return cachedState;
}

/**
 * Parse and semantically check a query.
 * Returns { errors: [{message, line, column}], columns: [{name, type}] | null }.
 */
function analyze(query, schemas, { withTables = true } = {}) {
  const state = withTables ? globalState(schemas) : K.GlobalState.Default;
  const code = K.KustoCode.ParseAndAnalyze(query, state);
  const diagnostics = code.GetDiagnostics();
  const errors = [];
  for (let i = 0; i < diagnostics.Count; i++) {
    const d = diagnostics.getItem(i);
    if (String(d.Severity) !== 'Error') continue;
    const before = query.slice(0, d.Start);
    const line = before.split('\n').length;
    const column = d.Start - before.lastIndexOf('\n');
    errors.push({ message: d.Message, line, column });
  }
  let columns = null;
  const result = code.ResultType;
  if (result && result.Columns) {
    columns = [];
    for (let i = 0; i < result.Columns.Count; i++) {
      const c = result.Columns.getItem(i);
      columns.push({ name: c.Name, type: c.Type ? c.Type.Name : 'unknown' });
    }
  }
  return { errors, columns };
}

// ---------------------------------------------------------------- test data

const UNIT_MS = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/** Parse an offset like "-30m", "-2h", "90s", "-1d" into milliseconds. */
function parseOffset(value) {
  const match = /^([+-]?\d+(?:\.\d+)?)([smhd])$/.exec(String(value).trim());
  if (!match) throw new Error(`bad time offset '${value}' (use e.g. -30m, -2h, -90s, -1d)`);
  return Number(match[1]) * UNIT_MS[match[2]];
}

function kqlString(value) {
  return JSON.stringify(String(value));
}

function kqlLiteral(value, type) {
  const missing = value === undefined || value === null;
  switch (type) {
    case 'string':
      return missing ? '""' : kqlString(value);
    case 'datetime':
      return missing ? 'datetime(null)' : `datetime(${new Date(value).toISOString()})`;
    case 'dynamic':
      return missing ? 'dynamic(null)' : `dynamic(${JSON.stringify(value)})`;
    case 'int':
    case 'long':
      return missing ? `${type}(null)` : `${type}(${Math.trunc(Number(value))})`;
    case 'real':
      return missing ? 'real(null)' : `real(${Number(value)})`;
    case 'bool':
      return missing ? 'bool(null)' : String(Boolean(value));
    default:
      throw new Error(`unsupported column type '${type}'`);
  }
}

/** Expand `repeat`/`every` shorthand and turn `at` offsets into TimeGenerated values. */
function expandRows(rows, now) {
  const out = [];
  for (const row of rows || []) {
    const { at = '0m', repeat = 1, every = '0s', ...fields } = row;
    const start = now + parseOffset(at);
    const step = parseOffset(every);
    for (let i = 0; i < repeat; i++) {
      out.push({ TimeGenerated: new Date(start + i * step).toISOString(), ...fields });
    }
  }
  return out;
}

/** Build `let Table = datatable(...)[...];` for one table. */
function datatableLet(table, rows, schemas, now) {
  const columns = schemas[table];
  if (!columns) throw new Error(`no schema for table '${table}' in schemas/tables.yaml`);
  for (const row of rows || []) {
    for (const key of Object.keys(row)) {
      if (!['at', 'repeat', 'every'].includes(key) && !(key in columns)) {
        throw new Error(`column '${key}' is not in the ${table} schema`);
      }
    }
  }
  const header = Object.entries(columns).map(([name, type]) => `['${name}']:${type}`).join(', ');
  const values = expandRows(rows, now)
    .map((row) => Object.entries(columns).map(([name, type]) => kqlLiteral(row[name], type)).join(', '));
  return `let ${table} = datatable(${header})[\n${values.join(',\n')}\n];`;
}

/** Tables a rule reads, from its requiredDataConnectors entries. */
function ruleTables(rule) {
  const tables = new Set();
  for (const connector of rule.requiredDataConnectors || []) {
    for (const t of connector.dataTypes || []) tables.add(t);
  }
  return [...tables];
}

/** The full query for one test case: a datatable per table, then the rule's own query. */
function buildTestQuery(rule, testCase, schemas, now = Date.now()) {
  const data = testCase.data || {};
  for (const table of Object.keys(data)) {
    if (!ruleTables(rule).includes(table)) {
      throw new Error(`test data for '${table}', which the rule does not list in requiredDataConnectors`);
    }
  }
  const lets = ruleTables(rule).map((table) => datatableLet(table, data[table] || [], schemas, now));
  return lets.join('\n') + '\n' + rule.query.trim();
}

module.exports = {
  ROOT, loadSchemas, loadRules, analyze, buildTestQuery, ruleTables, parseOffset, kqlLiteral, expandRows,
};

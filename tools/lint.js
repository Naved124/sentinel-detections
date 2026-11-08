#!/usr/bin/env node
// Static checks for every rule: required fields, ATT&CK fields, KQL syntax and semantics
// against the table schemas, entity mappings pointing at real output columns, and test coverage.
'use strict';

const { loadRules, loadSchemas, analyze, ruleTables } = require('./lib');

const SEVERITIES = ['Informational', 'Low', 'Medium', 'High'];
const TACTICS = ['Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution', 'Persistence',
  'PrivilegeEscalation', 'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection',
  'CommandAndControl', 'Exfiltration', 'Impact'];
const OPERATORS = ['gt', 'lt', 'eq', 'ne'];
const ENTITY_TYPES = ['Account', 'Host', 'IP', 'AzureResource', 'CloudApplication', 'Process', 'URL'];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DURATION = /^\d+[mhd]$/;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;

function lintRule(rule, schemas, seen) {
  const problems = [];
  const need = (cond, msg) => { if (!cond) problems.push(msg); };

  need(GUID.test(rule.id || ''), 'id must be a lowercase GUID');
  need(!seen.ids.has(rule.id), `duplicate id ${rule.id}`);
  need(/^[A-Z]+-\d{3}$/.test(rule.ruleId || ''), 'ruleId must look like SIGNIN-001');
  need(!seen.ruleIds.has(rule.ruleId), `duplicate ruleId ${rule.ruleId}`);
  need(rule.file === `${rule.ruleId}.yaml`, `file name should be ${rule.ruleId}.yaml`);
  seen.ids.add(rule.id); seen.ruleIds.add(rule.ruleId);

  need(typeof rule.name === 'string' && rule.name.length > 5, 'name is missing');
  need(typeof rule.description === 'string' && rule.description.length > 20, 'description is missing or too short');
  need(SEVERITIES.includes(rule.severity), `severity must be one of ${SEVERITIES.join(', ')}`);
  need(rule.kind === 'Scheduled', 'kind must be Scheduled');
  need(DURATION.test(rule.queryFrequency || ''), 'queryFrequency must look like 1h');
  need(DURATION.test(rule.queryPeriod || ''), 'queryPeriod must look like 1h');
  need(OPERATORS.includes(rule.triggerOperator), 'triggerOperator must be gt, lt, eq or ne');
  need(Number.isInteger(rule.triggerThreshold), 'triggerThreshold must be an integer');
  need(Array.isArray(rule.tactics) && rule.tactics.length > 0, 'tactics is empty');
  for (const t of rule.tactics || []) need(TACTICS.includes(t), `unknown tactic ${t}`);
  need(Array.isArray(rule.relevantTechniques) && rule.relevantTechniques.length > 0, 'relevantTechniques is empty');
  for (const t of rule.relevantTechniques || []) need(TECHNIQUE.test(t), `bad technique id ${t}`);
  need(ruleTables(rule).length > 0, 'requiredDataConnectors lists no dataTypes');
  for (const table of ruleTables(rule)) need(table in schemas, `no schema for table ${table}`);

  // Triage playbook
  const triage = rule.triage || {};
  need(Array.isArray(triage.steps) && triage.steps.length >= 3, 'triage.steps needs at least 3 steps');
  need(Array.isArray(triage.falsePositives) && triage.falsePositives.length >= 1, 'triage.falsePositives is empty');
  need(typeof triage.escalateWhen === 'string' && triage.escalateWhen.length > 10, 'triage.escalateWhen is missing');

  // Tests: at least one case that must fire and one that must stay quiet
  const tests = rule.tests || [];
  need(tests.some((t) => (t.expect || {}).rows > 0), 'needs a test that expects the rule to fire');
  need(tests.some((t) => (t.expect || {}).rows === 0), 'needs a test that expects no alert');
  for (const t of tests) need(typeof t.name === 'string' && t.expect && Number.isInteger(t.expect.rows),
    `test '${t.name || '?'}' needs a name and expect.rows`);

  // KQL
  if (typeof rule.query !== 'string' || !rule.query.trim()) {
    problems.push('query is empty');
    return problems;
  }
  const { errors, columns } = analyze(rule.query, schemas);
  for (const e of errors) problems.push(`KQL line ${e.line}:${e.column}: ${e.message}`);
  if (/\bago\(\s*\d+[smhd]\s*\)/.test(rule.query) && !/\blookback\b/.test(rule.query)) {
    problems.push('use a `let lookback = ...;` variable instead of a hard-coded ago()');
  }

  const outputs = new Set((columns || []).map((c) => c.name));
  need(Array.isArray(rule.entityMappings) && rule.entityMappings.length > 0, 'entityMappings is empty');
  for (const mapping of rule.entityMappings || []) {
    need(ENTITY_TYPES.includes(mapping.entityType), `unknown entityType ${mapping.entityType}`);
    for (const field of mapping.fieldMappings || []) {
      if (errors.length === 0) {
        need(outputs.has(field.columnName),
          `entity mapping ${mapping.entityType}.${field.identifier} uses '${field.columnName}', which the query does not output`);
      }
    }
  }
  return problems;
}

function main() {
  const schemas = loadSchemas();
  const rules = loadRules();
  const seen = { ids: new Set(), ruleIds: new Set() };
  let failed = 0;
  for (const rule of rules) {
    const problems = lintRule(rule, schemas, seen);
    if (problems.length) {
      failed++;
      console.log(`✗ ${rule.file}`);
      for (const p of problems) console.log(`    ${p}`);
    } else {
      console.log(`✓ ${rule.file}`);
    }
  }
  console.log(`\n${rules.length - failed}/${rules.length} rules passed lint`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main();
module.exports = { lintRule };

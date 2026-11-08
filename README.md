# sentinel-detections

Microsoft Sentinel detection rules written in KQL, mapped to MITRE ATT&CK, with automated tests and a triage playbook for every rule.

Each rule is one YAML file in [`rules/`](rules/) holding the analytics rule (query, schedule, severity, tactics, entity mappings), an analyst playbook (what to check, common false positives, when to escalate) and test cases that prove the rule fires on attack data and stays quiet on normal activity.

**15 rules** across Entra ID sign-ins, Entra ID audit logs, Azure activity logs and Linux syslog. The full list with ATT&CK coverage is in [`docs/RULES.md`](docs/RULES.md).

| Area | Rules |
|---|---|
| Entra ID sign-ins | password spraying, sign-in after brute force, MFA fatigue, impossible travel, legacy authentication |
| Entra ID audit | privileged role assigned, credential added to an app, Conditional Access policy disabled |
| Azure activity | NSG opening SSH/RDP/database ports to the internet, Owner/Contributor assigned, VM Run Command, logging removed |
| Linux (Syslog) | SSH brute force, SSH login after failures, sudo to a root shell or sensitive file |

## How testing works

Every test case lists log rows for the tables the rule reads. The test runner turns those rows into `let` datatables that shadow the real table names, places the timestamps relative to now, prepends them to the rule's query and runs it on the **Kusto emulator**, Microsoft's free Docker image of the same query engine Sentinel uses. No Azure subscription is needed.

```yaml
tests:
  - name: twelve failures then a success from the same IP fires
    data:
      SigninLogs:
        - { at: -40m, repeat: 12, every: 30s, UserPrincipalName: bob@example.com, IPAddress: 203.0.113.60, ResultType: "50126" }
        - { at: -30m, UserPrincipalName: bob@example.com, IPAddress: 203.0.113.60, ResultType: "0" }
    expect:
      rows: 1
      match: { UserPrincipalName: bob@example.com, FailedAttempts: 12 }
```

Each rule needs at least one case that must fire and one that must not, so tuning a threshold can't silently break detection or turn a rule into noise.

On top of the tests, `npm run lint` checks every rule without any engine, using Microsoft's own KQL parser (`Kusto.Language`):

- the query parses and every table, column and function exists in the [table schemas](schemas/tables.yaml)
- every entity mapping points at a column the query actually outputs
- required Sentinel fields, valid severities, tactics and ATT&CK technique IDs, unique GUIDs
- a playbook with triage steps, false positives and escalation criteria

## Run it

```console
npm ci
npm run lint                 # static checks, no engine needed
npm run test:offline         # check every generated test query is valid KQL

docker run -e ACCEPT_EULA=Y -m 4G -d -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
npm test                     # run all test cases on the emulator
npm test -- SIGNIN-003       # one rule
```

`KUSTO_URL` and `KUSTO_DB` point the runner at a different engine (defaults: `http://localhost:8080`, `NetDefaultDB`).

CI ([`.github/workflows/detections.yml`](.github/workflows/detections.yml)) runs lint, starts the emulator as a service container, runs every test case and checks that the generated docs are current.

## Repository layout

```text
rules/            one YAML per rule: query, schedule, ATT&CK, entities, triage, tests
schemas/          column names and types of the Sentinel tables the rules read
tools/lint.js     static checks with Kusto.Language
tools/test.js     test runner (Kusto emulator REST API)
tools/docs.js     generates docs/RULES.md and docs/playbooks/
docs/             generated rule index, ATT&CK coverage and playbooks
```

## Writing a rule

1. Copy a rule in `rules/`, give it a new `ruleId` and a new GUID (`uuidgen | tr A-Z a-z`).
2. Use `let lookback = ...;` for the time window so tests and the scheduler agree.
3. Add test cases for the attack and for the closest normal behaviour.
4. `npm run lint && npm test && npm run docs`.

## Notes and limits

- The YAML follows the Sentinel analytics rule template format. The `ruleId`, `triage` and `tests` keys are extra and are dropped when a rule is deployed.
- Ingesting Entra ID `SigninLogs` into Sentinel needs an Entra ID P1 or P2 licence. The sign-in rules are tested against sample data here.
- Test data uses documentation-only IP ranges (RFC 5737) and `example.com` accounts.

## License

MIT

# AZACT-004: Logging or security monitoring removed in Azure

**Severity:** High · **Tactics:** Defense Evasion · **Techniques:** [T1562.008](https://attack.mitre.org/techniques/T1562/008/) · **Data:** AzureActivity

A diagnostic setting, Log Analytics workspace, activity log alert or Sentinel analytics rule
was deleted. Removing logging and detections is how attackers hide what they do next, so this
should always be explained by a change record.

## Triage steps

1. Identify exactly what stopped being logged or detected, using _ResourceId.
2. Confirm the deletion with the Caller and change records.
3. Review everything the Caller did in Azure in the hours before and after TimeGenerated.
4. Restore the setting or rule, then search other data sources for activity during the gap.

## Common false positives

- Planned clean-up of test resources or decommissioned workspaces.
- Infrastructure-as-code redeployments that delete and recreate diagnostic settings.

## Escalate when

Escalate if the deletion was not planned, or if the Caller's other activity around the same
time looks unusual.

## Query

```kql
let lookback = 1h;
let logging_deletes = dynamic([
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DATASOURCES/DELETE",
    "MICROSOFT.INSIGHTS/ACTIVITYLOGALERTS/DELETE",
    "MICROSOFT.INSIGHTS/DATACOLLECTIONRULES/DELETE",
    "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE",
    "MICROSOFT.SECURITYINSIGHTS/DATACONNECTORS/DELETE"]);
AzureActivity
| where TimeGenerated > ago(lookback)
| where toupper(OperationNameValue) in (logging_deletes)
| summarize arg_max(TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, _ResourceId)
    by CorrelationId
| extend WhatWasRemoved = case(
    OperationNameValue has "DIAGNOSTICSETTINGS", "diagnostic setting",
    OperationNameValue has "DATASOURCES", "workspace data source",
    OperationNameValue has "WORKSPACES", "Log Analytics workspace",
    OperationNameValue has "ACTIVITYLOGALERTS", "activity log alert",
    OperationNameValue has "DATACOLLECTIONRULES", "data collection rule",
    OperationNameValue has "ALERTRULES", "Sentinel analytics rule",
    OperationNameValue has "DATACONNECTORS", "Sentinel data connector",
    "logging resource")
| project TimeGenerated, WhatWasRemoved, FinalStatus = ActivityStatusValue, Caller, CallerIpAddress, _ResourceId,
    OperationNameValue, CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AZACT-004.yaml`](../../rules/AZACT-004.yaml)

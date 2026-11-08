# AUDIT-002: New credential added to an app registration or service principal

**Severity:** High · **Tactics:** Persistence, Privilege Escalation · **Techniques:** [T1098.001](https://attack.mitre.org/techniques/T1098/001/) · **Data:** AuditLogs

A client secret or certificate was added to an application or service principal. Attackers add
their own credential to an existing app that already has broad API permissions, then sign in as
that app - access that survives password resets and does not need MFA.

## Triage steps

1. Check which API permissions the app holds (Microsoft Graph Mail.Read, Directory.ReadWrite.All and similar make this critical).
2. Ask the app's owner and the Initiator whether a secret or certificate rotation was planned.
3. Look for sign-ins by the service principal (AADServicePrincipalSignInLogs) after TimeGenerated from unfamiliar IPs.
4. Check the Initiator's own sign-ins for compromise around TimeGenerated.
5. If unplanned, remove the new credential, review what the app accessed, and reset the Initiator's credentials.

## Common false positives

- Scheduled secret or certificate rotation by the app's owners or by automation.
- CI/CD pipelines that create short-lived credentials for deployments.

## Escalate when

Escalate if no owner confirms it and the app holds tenant-wide or mail/file-read permissions.

## Query

```kql
let lookback = 1h;
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Add service principal credentials",
    "Update application – Certificates and secrets management")
| where Result =~ "success"
| mv-expand TargetResource = TargetResources
| extend AppName = tostring(TargetResource.displayName),
         AppObjectId = tostring(TargetResource.id),
         TargetType = tostring(TargetResource.type),
         InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
         InitiatedByApp = tostring(InitiatedBy.app.displayName),
         InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| where isnotempty(AppName)
| extend Initiator = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| project TimeGenerated, OperationName, AppName, AppObjectId, TargetType, Initiator, InitiatorIP, CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AUDIT-002.yaml`](../../rules/AUDIT-002.yaml)

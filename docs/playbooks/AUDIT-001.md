# AUDIT-001: Privileged Entra ID role assigned

**Severity:** High · **Tactics:** Persistence, Privilege Escalation · **Techniques:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) · **Data:** AuditLogs

A user was added to a highly privileged Microsoft Entra ID role such as Global Administrator or
Privileged Role Administrator. Attackers who take over an admin account add a second account
they control so they keep access after the first one is cleaned up.

## Triage steps

1. Find the change request or ticket for this assignment. Privileged role grants should never be a surprise.
2. Ask the Initiator, out of band, whether they made the change.
3. Check the Initiator's sign-ins around TimeGenerated - location, device, MFA - for signs the admin account itself was compromised.
4. Check TargetUser - is it a new account, a guest, or an account with recent risky sign-ins?
5. If unauthorised, remove the role, disable TargetUser, and investigate the Initiator account as compromised.

## Common false positives

- Planned admin onboarding or a scheduled Privileged Identity Management (PIM) assignment.
- Break-glass account maintenance done by the identity team.

## Escalate when

Escalate if there is no approved change, if the Initiator denies it, or if the role is
Global Administrator or Privileged Role Administrator and TargetUser is new or a guest.

## Query

```kql
let lookback = 1h;
let privileged_roles = dynamic(["Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Security Administrator", "Application Administrator",
    "Cloud Application Administrator", "User Administrator", "Exchange Administrator",
    "Conditional Access Administrator", "Hybrid Identity Administrator", "Authentication Administrator"]);
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Add member to role", "Add eligible member to role", "Add member to role outside of PIM (permanent)")
| where Result =~ "success"
| mv-expand TargetResource = TargetResources
| mv-expand ModifiedProperty = TargetResource.modifiedProperties
| where tostring(ModifiedProperty.displayName) == "Role.DisplayName"
| extend RoleName = trim(@'"', tostring(ModifiedProperty.newValue))
| where RoleName in (privileged_roles)
| extend TargetUser = tostring(TargetResource.userPrincipalName),
         InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
         InitiatedByApp = tostring(InitiatedBy.app.displayName),
         InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| where isnotempty(TargetUser)
| extend Initiator = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| project TimeGenerated, OperationName, RoleName, TargetUser, Initiator, InitiatorIP, CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AUDIT-001.yaml`](../../rules/AUDIT-001.yaml)

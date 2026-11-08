# AUDIT-003: Conditional Access policy deleted or disabled

**Severity:** High · **Tactics:** Defense Evasion, Persistence · **Techniques:** [T1556.009](https://attack.mitre.org/techniques/T1556/009/) · **Data:** AuditLogs

A Conditional Access policy was deleted or switched off. Conditional Access is what enforces MFA,
blocks legacy authentication and restricts risky sign-ins, so turning a policy off quietly
removes those protections for everyone it covered.

## Triage steps

1. Identify what the policy enforced (MFA for all users, admin MFA, legacy auth block, location restrictions).
2. Confirm with the identity team whether a change was approved. Policy changes should go through change control.
3. Check the Initiator's sign-ins around TimeGenerated for signs of compromise.
4. Look for sign-ins that the policy would have blocked or challenged, starting from TimeGenerated.
5. If unapproved, restore the policy and investigate the Initiator account.

## Common false positives

- Planned policy clean-up or replacement by the identity team.
- Temporarily disabling a policy while troubleshooting a sign-in issue.

## Escalate when

Escalate if the change was not approved or the policy enforced MFA or blocked legacy
authentication.

## Query

```kql
let lookback = 1h;
let changes = AuditLogs
    | where TimeGenerated > ago(lookback)
    | where Result =~ "success"
    | where OperationName in ("Delete conditional access policy", "Update conditional access policy")
    | mv-expand TargetResource = TargetResources;
let deleted = changes
    | where OperationName == "Delete conditional access policy"
    | extend Change = "deleted";
// An update only matters when the policy's new state is disabled (re-enabling one is fine).
let disabled = changes
    | where OperationName == "Update conditional access policy"
    | mv-expand ModifiedProperty = TargetResource.modifiedProperties
    | where tostring(ModifiedProperty.newValue) matches regex @'state\W{1,6}disabled'
    | extend Change = "disabled"
    | project-away ModifiedProperty;
union deleted, disabled
| extend PolicyName = tostring(TargetResource.displayName),
         InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
         InitiatedByApp = tostring(InitiatedBy.app.displayName),
         InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| extend Initiator = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| summarize arg_max(TimeGenerated, Initiator, InitiatorIP) by CorrelationId, PolicyName, Change
| project TimeGenerated, PolicyName, Change, Initiator, InitiatorIP, CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AUDIT-003.yaml`](../../rules/AUDIT-003.yaml)

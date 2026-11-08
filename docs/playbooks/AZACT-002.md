# AZACT-002: Owner, Contributor or User Access Administrator role assigned in Azure

**Severity:** High · **Tactics:** Privilege Escalation, Persistence · **Techniques:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) · **Data:** AzureActivity

Someone was granted Owner, Contributor or User Access Administrator on an Azure scope. These
roles allow full control of resources (and, for Owner and User Access Administrator, granting
access to others), so a new assignment is a common persistence and escalation step.

## Triage steps

1. Resolve PrincipalId to a user, group or service principal and check whether it is new.
2. Confirm the assignment with the Caller and against change records.
3. Check the scope - an assignment on a whole subscription or management group is far more serious than on one resource group.
4. Review the Caller's sign-ins around TimeGenerated for compromise.
5. If unauthorised, remove the assignment and review what the principal did with it.

## Common false positives

- Infrastructure-as-code pipelines that assign roles to new managed identities.
- Planned onboarding of a new administrator or team.

## Escalate when

Escalate if the Caller or change records do not explain it, or if Owner or User Access
Administrator was granted at subscription or management-group scope.

## Query

```kql
let lookback = 1h;
// Built-in role definition IDs are the same in every tenant.
let privileged_roles = dynamic({
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator"});
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| extend Body = parse_json(tostring(Properties_d.requestbody))
| extend Assignment = iff(isnotempty(Body.Properties), Body.Properties, Body.properties)
| where isnotempty(Assignment)
| extend RoleDefinitionId = tolower(tostring(coalesce(Assignment.RoleDefinitionId, Assignment.roleDefinitionId)))
| extend RoleGuid = extract(@"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", 1, RoleDefinitionId)
| extend RoleName = tostring(privileged_roles[RoleGuid])
| where isnotempty(RoleName)
| extend PrincipalId = tostring(coalesce(Assignment.PrincipalId, Assignment.principalId)),
         PrincipalType = tostring(coalesce(Assignment.PrincipalType, Assignment.principalType)),
         Scope = tostring(coalesce(Assignment.Scope, Assignment.scope))
| summarize arg_max(TimeGenerated, RoleName, PrincipalId, PrincipalType, Scope, Caller, CallerIpAddress, _ResourceId)
    by CorrelationId
| project TimeGenerated, RoleName, PrincipalId, PrincipalType, Scope, Caller, CallerIpAddress, _ResourceId, CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AZACT-002.yaml`](../../rules/AZACT-002.yaml)

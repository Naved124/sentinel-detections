# SIGNIN-003: MFA fatigue - repeated MFA denials for one account

**Severity:** High · **Tactics:** Credential Access · **Techniques:** [T1621](https://attack.mitre.org/techniques/T1621/) · **Data:** SigninLogs

An account denied three or more MFA prompts within an hour. Attackers who already have a
password send prompt after prompt hoping the user approves one to make them stop (MFA fatigue
or push bombing). The alert flags whether an MFA sign-in was approved after the denials began.

## Triage steps

1. If ApprovedAfterDenials is true, treat the account as compromised - the attacker likely got a prompt approved.
2. Call the user. Ask whether they were signing in themselves and whether they approved any prompt.
3. Compare SourceIPs and ApprovedFromIP with the user's usual locations and devices.
4. Review the account's activity after ApprovedAt - new MFA methods registered, mailbox rules, OAuth consents, file access.
5. Reset the password (the attacker already has it), revoke sessions, and move the user to number matching or phishing-resistant MFA.

## Common false positives

- A user tapping Deny by mistake on a prompt from their own laptop, then retrying.
- A misbehaving app on the user's device that keeps triggering MFA in the background.

## Escalate when

Escalate immediately if ApprovedAfterDenials is true, or if the user did not start any of the
sign-ins. Repeated denials mean the attacker already has the password.

## Query

```kql
let lookback = 1h;
let min_denials = 3;
let denials = SigninLogs
    | where TimeGenerated > ago(lookback)
    // 500121: authentication failed during the strong authentication (MFA) request
    | where ResultType == "500121"
    | extend Detail = tostring(Status.additionalDetails)
    | where Detail contains "denied" or Detail contains "declined" or Detail contains "fraud"
    | summarize Denials = count(), FirstDenial = min(TimeGenerated), LastDenial = max(TimeGenerated),
        SourceIPs = make_set(IPAddress, 20), Details = make_set(Detail, 5)
        by UserPrincipalName
    | where Denials >= min_denials;
let approvals = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0" and AuthenticationRequirement == "multiFactorAuthentication"
    | project ApprovedAt = TimeGenerated, UserPrincipalName, ApprovedFromIP = IPAddress;
denials
| join kind=leftouter approvals on UserPrincipalName
| extend ApprovedAt = iff(ApprovedAt > FirstDenial, ApprovedAt, datetime(null)),
         ApprovedFromIP = iff(ApprovedAt > FirstDenial, ApprovedFromIP, "")
| summarize ApprovedAt = min(ApprovedAt), ApprovedFromIP = take_anyif(ApprovedFromIP, isnotempty(ApprovedFromIP))
    by UserPrincipalName, Denials, FirstDenial, LastDenial, tostring(SourceIPs), tostring(Details)
| extend ApprovedAfterDenials = isnotnull(ApprovedAt)
| project UserPrincipalName, Denials, FirstDenial, LastDenial, ApprovedAfterDenials, ApprovedAt, ApprovedFromIP,
    SourceIPs = todynamic(SourceIPs), Details = todynamic(Details)
```

Runs every 1h over the last 1h. Source: [`rules/SIGNIN-003.yaml`](../../rules/SIGNIN-003.yaml)

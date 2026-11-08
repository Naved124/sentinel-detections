# SIGNIN-002: Successful Entra ID sign-in after brute force

**Severity:** High · **Tactics:** Credential Access, Initial Access · **Techniques:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) · **Data:** SigninLogs

An account had ten or more failed sign-ins from one IP address and then signed in successfully
from that same IP within the hour. The failures alone are noise on any internet-facing tenant;
the success afterwards is what makes this worth an analyst's time.

## Triage steps

1. Check AuthenticationRequirement. singleFactorAuthentication means the password alone was enough, which is the worst case.
2. Ask the user, through a channel other than their account, whether they signed in at SuccessTime from that location.
3. Review everything the account did after SuccessTime - mailbox rules, file downloads, MFA method changes, app consents, new devices.
4. Look up the IP and check whether it hit other accounts (see SIGNIN-001).
5. If not confirmed by the user, revoke sessions, reset the password and require MFA re-registration.

## Common false positives

- The user forgot a recently changed password, retried many times and then got it right.
- A phone or mail client kept retrying an old saved password before the user updated it.

## Escalate when

Escalate if the user does not confirm the sign-in, if the sign-in was single-factor, or if
the account holds an admin role.

## Query

```kql
let lookback = 1h;
let min_failures = 10;
let failures = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType in ("50126", "50053")
    | summarize FailedAttempts = count(), FirstFailure = min(TimeGenerated), LastFailure = max(TimeGenerated)
        by UserPrincipalName, IPAddress
    | where FailedAttempts >= min_failures;
let successes = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0"
    | project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed, AuthenticationRequirement;
failures
| join kind=inner successes on UserPrincipalName, IPAddress
| where SuccessTime > FirstFailure
| summarize arg_min(SuccessTime, AppDisplayName, ClientAppUsed, AuthenticationRequirement)
    by UserPrincipalName, IPAddress, FailedAttempts, FirstFailure, LastFailure
| project UserPrincipalName, IPAddress, FailedAttempts, FirstFailure, LastFailure, SuccessTime,
    AppDisplayName, ClientAppUsed, AuthenticationRequirement
```

Runs every 1h over the last 1h. Source: [`rules/SIGNIN-002.yaml`](../../rules/SIGNIN-002.yaml)

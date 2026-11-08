# SIGNIN-001: Password spraying against Entra ID from one IP

**Severity:** Medium · **Tactics:** Credential Access · **Techniques:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) · **Data:** SigninLogs

One IP address failed to sign in as five or more different accounts within an hour. Password
spraying tries one or two common passwords against many accounts to stay under per-account
lockout limits. The alert also lists any of the targeted accounts that then signed in
successfully from the same IP, which is the case to investigate first.

## Triage steps

1. Check CompromisedCount first. Any account listed there signed in from the spraying IP, so treat it as compromised until shown otherwise.
2. Look up the IP (owner, ASN, hosting or VPN provider, reputation). Spraying almost always comes from cloud hosting, VPNs or proxies.
3. For each compromised account, review its sign-ins after the success time - new devices, new countries, mailbox rules, MFA method changes, app consents.
4. Check whether the same IP appears in other alerts or against other tenants you monitor.
5. Contain compromised accounts - revoke sessions, reset the password, require MFA re-registration.

## Common false positives

- A shared corporate egress IP or VPN gateway where many users mistype passwords after a password policy change.
- An internal tool or migration script using stale credentials for several service accounts.

## Escalate when

Escalate immediately if CompromisedCount is above zero, or if the targeted accounts include
administrators or executives.

## Query

```kql
let lookback = 1h;
let min_accounts = 5;
// 50126 bad username or password, 50053 locked or blocked, 50055 expired, 50056 invalid or null password
let failure_codes = dynamic(["50126", "50053", "50055", "50056"]);
let failures = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType in (failure_codes)
    | summarize
        TargetedAccounts = dcount(UserPrincipalName),
        FailedAttempts = count(),
        Accounts = make_set(UserPrincipalName, 100),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress
    | where TargetedAccounts >= min_accounts;
let successes = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0"
    | summarize SucceededAccounts = make_set(UserPrincipalName, 100) by IPAddress;
failures
| join kind=leftouter successes on IPAddress
| extend CompromisedAccounts = set_intersect(Accounts, coalesce(SucceededAccounts, dynamic([])))
| extend CompromisedCount = array_length(CompromisedAccounts)
| project IPAddress, TargetedAccounts, FailedAttempts, CompromisedCount, CompromisedAccounts, Accounts, FirstSeen, LastSeen
```

Runs every 1h over the last 1h. Source: [`rules/SIGNIN-001.yaml`](../../rules/SIGNIN-001.yaml)

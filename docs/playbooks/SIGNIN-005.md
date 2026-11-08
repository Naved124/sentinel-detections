# SIGNIN-005: Successful sign-in with legacy authentication

**Severity:** Medium · **Tactics:** Initial Access, Defense Evasion · **Techniques:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) · **Data:** SigninLogs

An account signed in successfully over a legacy authentication protocol such as IMAP, POP3,
SMTP AUTH or Exchange ActiveSync with basic auth. These protocols cannot do MFA, so attackers
with a sprayed or leaked password use them to get around MFA and Conditional Access.

## Triage steps

1. Check whether this user has a known reason to use the protocol (an old printer or scanner sending mail, a legacy app).
2. Look up AllIPs. Legacy-auth abuse typically comes from hosting providers rather than the user's normal networks.
3. Check the mailbox for new inbox rules, forwarding, or bulk reads after FirstSeen.
4. If it is not a known device, reset the password and block legacy authentication with Conditional Access.

## Common false positives

- Multifunction printers or scanners using SMTP AUTH to send scans by email.
- Old mail clients or line-of-business apps that were never moved to modern authentication.

## Escalate when

Escalate if no known device explains it, if the IPs are hosting or VPN ranges, or if the
mailbox shows rules or forwarding added after the sign-in.

## Query

```kql
let lookback = 1h;
let legacy_clients = dynamic(["Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP",
    "Exchange Web Services", "MAPI Over HTTP", "Offline Address Book", "Other clients", "AutoDiscover",
    "Exchange Online PowerShell", "Outlook Anywhere (RPC over HTTP)", "Reporting Web Services", "Universal Outlook"]);
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where ClientAppUsed in (legacy_clients)
| summarize SignIns = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    IPAddress = take_any(IPAddress), AllIPs = make_set(IPAddress, 20), Apps = make_set(AppDisplayName, 10),
    UserAgents = make_set(UserAgent, 10)
    by UserPrincipalName, ClientAppUsed
```

Runs every 1h over the last 1h. Source: [`rules/SIGNIN-005.yaml`](../../rules/SIGNIN-005.yaml)

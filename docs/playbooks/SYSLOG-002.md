# SYSLOG-002: Successful SSH login after repeated failures from the same IP

**Severity:** High · **Tactics:** Credential Access, Initial Access · **Techniques:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078.003](https://attack.mitre.org/techniques/T1078/003/) · **Data:** Syslog

A Linux host accepted an SSH login from an IP address that had already failed five or more
times in the same hour. This is the point where an SSH brute force or password guess stops
being noise and becomes a likely compromise.

## Triage steps

1. Check AuthMethod. A password login after failures is a likely successful guess; a publickey login after password failures may be a person who switched to their key.
2. Ask the owner of AcceptedUser whether they logged in from SourceIP at LoginTime.
3. On the host, review what the session did - shell history, sudo use (SYSLOG-003), new users, cron entries, authorized_keys changes, outbound connections.
4. If not confirmed, isolate the host, kill the session, rotate the account's credentials and keys.

## Common false positives

- A user who mistyped their password several times and then got it right.
- A user whose client tried several keys or passwords before the right one.

## Escalate when

Escalate if the login was by password, if the owner does not confirm it, or if the account
then used sudo.

## Query

```kql
let lookback = 1h;
let min_failures = 5;
let ssh = Syslog
    | where TimeGenerated > ago(lookback)
    | where ProcessName in ("sshd", "sshd-session")
    | extend SourceIP = extract(@"from (\S+) port \d+", 1, SyslogMessage);
let failures = ssh
    | where SyslogMessage startswith "Failed "
    | summarize FailedAttempts = count(), FirstFailure = min(TimeGenerated), LastFailure = max(TimeGenerated)
        by Computer, SourceIP
    | where FailedAttempts >= min_failures;
let logins = ssh
    | where SyslogMessage startswith "Accepted "
    | extend AcceptedUser = extract(@"Accepted \S+ for (\S+) from", 1, SyslogMessage),
             AuthMethod = extract(@"Accepted (\S+) for", 1, SyslogMessage)
    | project LoginTime = TimeGenerated, Computer, SourceIP, AcceptedUser, AuthMethod;
failures
| join kind=inner logins on Computer, SourceIP
| where LoginTime > FirstFailure
| summarize arg_min(LoginTime, AcceptedUser, AuthMethod) by Computer, SourceIP, FailedAttempts, FirstFailure, LastFailure
| project Computer, SourceIP, AcceptedUser, AuthMethod, FailedAttempts, FirstFailure, LastFailure, LoginTime
```

Runs every 1h over the last 1h. Source: [`rules/SYSLOG-002.yaml`](../../rules/SYSLOG-002.yaml)

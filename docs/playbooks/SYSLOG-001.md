# SYSLOG-001: SSH brute force against a Linux host

**Severity:** Low · **Tactics:** Credential Access · **Techniques:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · **Data:** Syslog

One source IP produced ten or more failed SSH logins against a Linux host within ten minutes.
On an internet-facing server this is constant background noise, so the rule is tuned for
awareness and for correlation with SYSLOG-002, which catches the brute force that worked.

## Triage steps

1. Check whether SYSLOG-002 also fired for the same host and IP. If so, work that alert first.
2. Look at Usernames. Guessing real account names (not just root, admin, test) suggests a targeted attack.
3. Confirm the host should accept SSH from the internet at all (see AZACT-001 for recently opened ports).
4. Make sure password authentication is disabled (PasswordAuthentication no) and consider fail2ban or restricting the source range.

## Common false positives

- Internet background scanning against any host with port 22 open.
- An automation account with an expired key retrying in a loop.

## Escalate when

Escalate if real usernames are being targeted, if the host is not supposed to be reachable,
or if any login from the same IP succeeded.

## Query

```kql
let lookback = 1h;
let window = 10m;
// Fires when any 10 consecutive failures from one IP fall inside the window (a true sliding
// window, so a burst that straddles a clock boundary is not split in two).
Syslog
| where TimeGenerated > ago(lookback)
// OpenSSH 9.8+ logs authentication from sshd-session instead of sshd
| where ProcessName in ("sshd", "sshd-session")
| where SyslogMessage startswith "Failed "
| extend SourceIP = extract(@"from (\S+) port \d+", 1, SyslogMessage),
         TargetUser = extract(@"for (?:invalid user )?(\S+) from", 1, SyslogMessage),
         InvalidUser = SyslogMessage has "invalid user"
| where isnotempty(SourceIP)
| extend Key = strcat(Computer, "|", SourceIP)
| sort by Key asc, TimeGenerated asc
| extend StartKey = prev(Key, 9), StartTime = prev(TimeGenerated, 9)
| extend BurstEnd = StartKey == Key and TimeGenerated - StartTime <= window
| summarize FailedAttempts = count(), InvalidUserAttempts = countif(InvalidUser), Bursts = countif(BurstEnd),
    Usernames = make_set(TargetUser, 25), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Computer, SourceIP
| where Bursts > 0
| project Computer, SourceIP, FailedAttempts, InvalidUserAttempts, Usernames, FirstSeen, LastSeen
```

Runs every 1h over the last 1h. Source: [`rules/SYSLOG-001.yaml`](../../rules/SYSLOG-001.yaml)

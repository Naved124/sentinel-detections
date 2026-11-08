# SYSLOG-003: Sudo used for a root shell or a sensitive change

**Severity:** Medium · **Tactics:** Privilege Escalation · **Techniques:** [T1548.003](https://attack.mitre.org/techniques/T1548/003/) · **Data:** Syslog

A user ran sudo to open a root shell, read credential files, edit sudoers, add users or set a
setuid bit. These are the first things an attacker does after landing on a Linux host, and they
are rare enough in normal administration to be worth a look.

## Triage steps

1. Check who SudoUser is and whether they normally administer this host.
2. Check how they logged in - correlate with SSH logins on the same host (SYSLOG-002).
3. Look at what followed in the logs and shell history - new users, changed keys, downloaded files, services or cron jobs.
4. If DeniedRuns is above zero, someone tried commands they are not allowed to run, which suggests a compromised low-privilege account.
5. If not expected, disable the account, rotate credentials on the host, and look for persistence.

## Common false positives

- Administrators opening a root shell for maintenance.
- Provisioning scripts that add users or set permissions during deployment.

## Escalate when

Escalate if the user does not normally administer the host, if credential files were read,
or if the session started from an SSH login flagged by SYSLOG-002.

## Query

```kql
let lookback = 1h;
let sensitive = @"(^|[\s/])(bash|sh|zsh|dash|su)(\s|$)|/etc/(shadow|gshadow|sudoers)|\.aws/credentials|\.ssh/authorized_keys|(^|[\s/])(visudo|useradd|adduser|usermod|passwd)(\s|$)|chmod\s+[ugoa]*\+s|chmod\s+[0-7]?[4-7][0-7]{3}\s";
Syslog
| where TimeGenerated > ago(lookback)
| where ProcessName == "sudo"
| where SyslogMessage has "COMMAND="
| extend SudoUser = trim(@"\s+", extract(@"^\s*(\S+)\s+:", 1, SyslogMessage)),
         RunAs = extract(@"USER=(\S+)\s*;", 1, SyslogMessage),
         Command = trim(@"\s+", extract(@"COMMAND=(.*)$", 1, SyslogMessage)),
         Denied = SyslogMessage has "incorrect password" or SyslogMessage has "NOT in sudoers" or SyslogMessage has "command not allowed"
| where Command matches regex sensitive
| summarize Commands = make_set(Command, 20), Runs = count(), DeniedRuns = countif(Denied),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Computer, SudoUser, RunAs
| project Computer, SudoUser, RunAs, Commands, Runs, DeniedRuns, FirstSeen, LastSeen
```

Runs every 1h over the last 1h. Source: [`rules/SYSLOG-003.yaml`](../../rules/SYSLOG-003.yaml)

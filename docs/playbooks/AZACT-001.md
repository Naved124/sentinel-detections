# AZACT-001: NSG rule opens a sensitive port to the internet

**Severity:** High · **Tactics:** Defense Evasion · **Techniques:** [T1562.007](https://attack.mitre.org/techniques/T1562/007/) · **Data:** AzureActivity

A network security group rule was created or changed to allow inbound traffic from any source
(*, Internet, 0.0.0.0/0) to a remote-access or database port such as SSH, RDP, MySQL or SQL
Server. Attackers open these ports to get back in; admins open them "temporarily" and forget.

## Triage steps

1. Check whether the rule is still there and what it protects (which VMs or subnets use the NSG).
2. Ask the Caller why the port was opened. Remote access should go through Bastion, a VPN or just-in-time access.
3. Check the Caller's sign-ins around TimeGenerated for signs the account was compromised.
4. Look for inbound connections or brute-force attempts on the exposed ports since TimeGenerated (see SYSLOG-001).
5. Remove or restrict the rule to known source IPs.

## Common false positives

- A short, approved change during an outage, already reverted.
- Lab or sandbox subscriptions that intentionally expose services.

## Escalate when

Escalate if the Caller did not make the change, if the NSG covers production workloads, or if
the exposed hosts show logins from new IPs after TimeGenerated.

## Query

```kql
let lookback = 1h;
let any_source = dynamic(["*", "0.0.0.0/0", "Internet", "Any", "::/0"]);
// SSH, RDP, WinRM, SMB, MySQL, MSSQL, PostgreSQL, Redis, MongoDB, Elasticsearch
let sensitive_ports = dynamic([22, 3389, 5985, 5986, 445, 3306, 1433, 5432, 6379, 27017, 9200]);
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue =~ "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| extend Rule = parse_json(tostring(Properties_d.requestbody)).properties
| where isnotempty(Rule)
| where tostring(Rule.direction) =~ "Inbound" and tostring(Rule.access) =~ "Allow"
| extend Sources = iff(isnotempty(tostring(Rule.sourceAddressPrefix)),
                       pack_array(tostring(Rule.sourceAddressPrefix)), Rule.sourceAddressPrefixes)
| where array_length(set_intersect(Sources, any_source)) > 0
| extend Ports = iff(isnotempty(tostring(Rule.destinationPortRange)),
                     pack_array(tostring(Rule.destinationPortRange)), Rule.destinationPortRanges)
| mv-expand Port = Ports to typeof(string)
| extend Bounds = split(Port, "-")
| extend Low = iff(Port == "*", 0, toint(Bounds[0])),
         High = iff(Port == "*", 65535, toint(Bounds[array_length(Bounds) - 1]))
| extend Candidates = sensitive_ports
| mv-apply Candidate = Candidates to typeof(int) on (where Candidate between (Low .. High))
| summarize ExposedPorts = make_set(Candidate), arg_max(TimeGenerated, Caller, CallerIpAddress, _ResourceId, Rule)
    by CorrelationId
| extend NsgName = tostring(split(_ResourceId, "/")[8]), RuleName = tostring(split(_ResourceId, "/")[10])
| project TimeGenerated, NsgName, RuleName, ExposedPorts, Caller, CallerIpAddress, _ResourceId,
    Protocol = tostring(Rule.protocol), Priority = toint(Rule.priority), CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AZACT-001.yaml`](../../rules/AZACT-001.yaml)

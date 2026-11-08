# AZACT-003: Command run on an Azure VM through Run Command

**Severity:** Medium · **Tactics:** Execution · **Techniques:** [T1651](https://attack.mitre.org/techniques/T1651/) · **Data:** AzureActivity

Someone used Azure Run Command to execute a script on a virtual machine. Run Command executes
as SYSTEM or root through the VM agent, needs no network access to the VM, and is a known way
for attackers with Azure permissions to run code on servers.

## Triage steps

1. Ask the Caller what was run and why. Run Command is rarely part of normal operations.
2. Get the script that ran from the VM's run command history (az vm run-command list) or the VM agent logs.
3. Check the Caller's sign-ins and other Azure activity around TimeGenerated.
4. On the VM, look for new users, scheduled tasks, services, cron jobs or outbound connections created after TimeGenerated.
5. If unexplained, isolate the VM and remove the Caller's Virtual Machine Contributor (or higher) access.

## Common false positives

- Administrators using Run Command for troubleshooting when SSH or RDP is unavailable.
- Configuration management or patching tools that use Run Command.

## Escalate when

Escalate if the Caller cannot explain the command, if the script downloads or launches
anything, or if the VM is production.

## Query

```kql
let lookback = 1h;
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue in~ (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/VIRTUALMACHINES/RUNCOMMAND/ACTION")
| summarize arg_max(TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, _ResourceId, ResourceGroup)
    by CorrelationId
| extend VmName = tostring(split(_ResourceId, "/")[8])
| project TimeGenerated, VmName, ResourceGroup, Caller, CallerIpAddress, FinalStatus = ActivityStatusValue,
    OperationNameValue, _ResourceId, CorrelationId
```

Runs every 1h over the last 1h. Source: [`rules/AZACT-003.yaml`](../../rules/AZACT-003.yaml)

# Lab 03 — Suspicious PowerShell & Process Execution Detection with Microsoft Sentinel

## Overview

This project demonstrates the detection and investigation of suspicious PowerShell command-line activity using Microsoft Sentinel.

A Windows Server endpoint previously onboarded to Microsoft Sentinel using Azure Monitor Agent (AMA) and a Data Collection Rule (DCR) was used to generate Windows process-creation telemetry.

Windows Event ID 4688 was collected into the `SecurityEvent` table.

Process command-line auditing was enabled on the endpoint to provide visibility into arguments passed to newly created processes.

Controlled PowerShell activity was then generated using command-line options commonly associated with suspicious execution, including:

- `-EncodedCommand`
- `-ExecutionPolicy Bypass`
- `-NoProfile`

Kusto Query Language (KQL) was used to hunt for the resulting process-creation activity and distinguish normal PowerShell execution from potentially suspicious command-line behaviour.

A custom Microsoft Sentinel scheduled analytics rule was created to detect encoded PowerShell commands or execution-policy bypass activity.

The rule successfully generated an alert and incident in Microsoft Defender.

The encoded PowerShell payload was then safely decoded during investigation to determine what the command actually performed.

The decoded payload was confirmed to contain only harmless lab activity.

The incident was subsequently classified as authorized security testing and resolved.

The project demonstrates the following workflow:

```text
PowerShell Execution
        ↓
Windows Event ID 4688
        ↓
Azure Monitor Agent
        ↓
Data Collection Rule
        ↓
SecurityEvent
        ↓
KQL Hunting
        ↓
Suspicious Command-Line Detection
        ↓
Scheduled Analytics Rule
        ↓
Alert
        ↓
Incident
        ↓
Payload Analysis
        ↓
SOC Investigation
        ↓
Classification
        ↓
Resolution
```

---

## Objectives

The objectives of this lab were to:

- Investigate Windows process-creation telemetry
- Understand Windows Event ID 4688
- Enable process command-line auditing
- Collect PowerShell command-line arguments in Microsoft Sentinel
- Use KQL to hunt for PowerShell execution
- Identify potentially suspicious PowerShell arguments
- Distinguish normal PowerShell usage from suspicious-looking activity
- Use KQL `extend` to enrich process telemetry
- Detect encoded PowerShell execution
- Detect PowerShell execution-policy bypass
- Create a scheduled Microsoft Sentinel analytics rule
- Map PowerShell activity to MITRE ATT&CK
- Generate a Sentinel alert and incident
- Investigate process ancestry
- Analyse the executing account
- Decode a Base64 PowerShell payload safely
- Determine whether the decoded command was malicious
- Classify and resolve the incident
- Validate entity mapping in the incident graph

---

## Technologies Used

- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender
- Microsoft Defender portal
- Windows Server
- Windows Security Event Logs
- Azure Monitor Agent
- Data Collection Rules
- Log Analytics
- Kusto Query Language
- PowerShell
- Windows Event ID 4688
- MITRE ATT&CK

---

## Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | Windows Server |
| Hostname | `SC200-WIN01` |
| SIEM | Microsoft Sentinel |
| Security Portal | Microsoft Defender |
| Log Collection | Azure Monitor Agent |
| Data Collection | Data Collection Rule |
| Sentinel Connector | Windows Security Events via AMA |
| Primary Table | `SecurityEvent` |
| Process Event | Windows Event ID 4688 |
| Shell | Windows PowerShell |
| Test User | `azureuser` |

All PowerShell activity was intentionally generated inside an authorized lab environment.

---

## Architecture

```text
┌────────────────────────────┐
│       SC200-WIN01          │
│       Windows Server       │
└─────────────┬──────────────┘
              │
              │ Process Execution
              ▼
┌────────────────────────────┐
│ Windows Security Event     │
│        ID 4688             │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│    Azure Monitor Agent     │
│            AMA             │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│    Data Collection Rule    │
│            DCR             │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│      Log Analytics         │
│       SecurityEvent        │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│     Microsoft Sentinel     │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│        KQL Hunting         │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│ Scheduled Analytics Rule   │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│           Alert            │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│          Incident          │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│ Payload & Process Analysis │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│         Resolution         │
└────────────────────────────┘
```

---

## 1. Verifying Process Creation Telemetry

Windows Event ID 4688 records the creation of a new process.

The following query was used to review process creation activity collected from the monitored endpoint:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

The query returned hundreds of process-creation events from:

```text
SC200-WIN01
```

This confirmed that Windows Event ID 4688 telemetry was successfully being ingested into Microsoft Sentinel.

However, the `CommandLine` field was initially empty.

### Screenshot

```text
screenshots/01-4688-process-events.png
```

---

## 2. Enabling Process Command-Line Auditing

Windows was generating Event ID 4688 events, but the command-line arguments used to launch the processes were not initially visible.

Process command-line auditing was enabled on `SC200-WIN01`.

The following PowerShell command was used:

```powershell
New-ItemProperty `
  -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" `
  -PropertyType DWord `
  -Value 1 `
  -Force
```

Group Policy was then refreshed:

```powershell
gpupdate /force
```

The setting was verified using:

```powershell
Get-ItemProperty `
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled
```

The expected value was:

```text
ProcessCreationIncludeCmdLine_Enabled : 1
```

---

## 3. Verifying Command-Line Telemetry

A harmless PowerShell command was executed to verify that command-line arguments were now included in Event ID 4688.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SC200-LAB-COMMANDLINE-TEST'"
```

The following query was then executed in Microsoft Sentinel:

```kusto
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

The newly generated event contained a populated `CommandLine` field.

This confirmed that command-line auditing was working.

### Screenshot

```text
screenshots/02-commandline-enabled.png
```

---

## 4. Generating Controlled Suspicious PowerShell Activity

A controlled encoded PowerShell command was generated.

The command itself was harmless.

First, the test payload was defined:

```powershell
$cmd = "Write-Output 'SC200-LAB-ENCODED-TEST'"
```

The command was converted to Unicode bytes:

```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
```

It was then Base64 encoded:

```powershell
$encoded = [Convert]::ToBase64String($bytes)
```

Finally, the encoded command was executed:

```powershell
powershell.exe -NoProfile -EncodedCommand $encoded
```

The command only produced:

```text
SC200-LAB-ENCODED-TEST
```

No malicious activity was performed.

The purpose was to generate telemetry that resembled a suspicious PowerShell execution pattern.

---

## 5. Hunting for Suspicious PowerShell Arguments

The following query was used to locate PowerShell processes using potentially suspicious command-line arguments:

```kusto
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-EncodedCommand"
    or CommandLine contains "-ExecutionPolicy Bypass"
    or CommandLine contains "-NoProfile"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

Two interesting executions were observed:

```text
PowerShell execution using -EncodedCommand
PowerShell execution using -ExecutionPolicy Bypass
```

This demonstrated that suspicious command-line patterns could be identified directly from Event ID 4688 telemetry.

### Screenshot

```text
screenshots/03-suspicious-powershell-hunt.png
```

---

## 6. Enriching PowerShell Telemetry with KQL

The investigation query was improved using the KQL `extend` operator.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| extend
    EncodedCommand = CommandLine contains "-EncodedCommand"
        or CommandLine contains "-enc ",
    ExecutionPolicyBypass = CommandLine contains "-ExecutionPolicy Bypass",
    NoProfile = CommandLine contains "-NoProfile"
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    NewProcessName,
    EncodedCommand,
    ExecutionPolicyBypass,
    NoProfile,
    CommandLine
| order by TimeGenerated desc
```

The resulting telemetry clearly distinguished between different PowerShell execution types.

Example:

```text
Execution 1
EncodedCommand: true
ExecutionPolicyBypass: false
NoProfile: true

Execution 2
EncodedCommand: false
ExecutionPolicyBypass: true
NoProfile: true

Execution 3
EncodedCommand: false
ExecutionPolicyBypass: false
NoProfile: false
```

This demonstrated how KQL can enrich raw telemetry into analyst-friendly fields.

### Screenshot

```text
screenshots/04-powershell-enrichment.png
```

---

## 7. Understanding the `extend` Operator

The `extend` operator was used to create calculated fields.

For example:

```kusto
| extend EncodedCommand = CommandLine contains "-EncodedCommand"
```

creates a new Boolean column named:

```text
EncodedCommand
```

The result is:

```text
true
```

when the command line contains the specified PowerShell argument.

Otherwise:

```text
false
```

This allows analysts to transform complex command-line telemetry into simple indicators that can be used for hunting and detection.

---

## 8. Isolating Encoded PowerShell Execution

The query was narrowed further to identify only encoded PowerShell execution:

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-EncodedCommand"
    or CommandLine contains "-enc "
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

This isolated the controlled encoded PowerShell event.

The event showed:

```text
Host:
SC200-WIN01

Account:
azureuser

Process:
powershell.exe

Encoded execution:
Yes
```

### Screenshot

```text
screenshots/05-encoded-powershell.png
```

---

## 9. Building the Detection Query

A detection query was developed to identify PowerShell execution containing either:

```text
-EncodedCommand
```

or:

```text
-ExecutionPolicy Bypass
```

The final detection query was:

```kusto
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend
    EncodedCommand = CommandLine contains "-EncodedCommand"
        or CommandLine contains "-enc ",
    ExecutionPolicyBypass = CommandLine contains "-ExecutionPolicy Bypass"
| where EncodedCommand or ExecutionPolicyBypass
| extend DetectionReason = case(
    EncodedCommand, "Encoded PowerShell command",
    ExecutionPolicyBypass, "Execution policy bypass",
    "Suspicious PowerShell execution"
)
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    NewProcessName,
    DetectionReason,
    EncodedCommand,
    ExecutionPolicyBypass,
    CommandLine
```

This detection intentionally did not alert on `-NoProfile` alone because that option can be used legitimately and would likely introduce unnecessary noise.

---

## 10. Detection Logic

The resulting detection logic was:

```text
Windows Event ID 4688
        ↓
Is the process PowerShell?
        ↓
Yes
        ↓
Does the command contain:
-EncodedCommand
OR
-ExecutionPolicy Bypass
        ↓
Yes
        ↓
Generate detection
```

This approach is more useful than alerting on every PowerShell execution.

PowerShell itself is a legitimate administrative tool.

The detection focuses instead on command-line characteristics that may require additional investigation.

---

## 11. Microsoft Sentinel Analytics Rule

The query was converted into a scheduled Microsoft Sentinel analytics rule.

### Rule Configuration

```text
Name:
Suspicious PowerShell Command-Line Execution

Severity:
Medium

Tactic:
Execution

MITRE ATT&CK:
T1059.001 — PowerShell
```

The rule description was:

```text
Detects PowerShell process creation containing encoded commands
or execution policy bypass arguments.
```

### Rule Schedule

```text
Run query every:
5 minutes

Lookup data from the last:
10 minutes

Alert threshold:
Greater than 0
```

The shorter lookback window was retained based on lessons learned during the previous failed-logon detection lab.

### Screenshot

```text
screenshots/06-analytics-rule-enabled.png
```

---

## 12. Alert Enrichment

The following fields were included as custom alert details:

```text
DetectionReason
CommandLine
ParentProcessName
Account
EncodedCommand
ExecutionPolicyBypass
```

This provided additional investigation context directly inside the alert.

---

## 13. Host Entity Mapping

The analytics rule also included host entity mapping.

The `Computer` field was mapped to a Host entity.

Unlike the previous authentication lab, the entity mapping successfully appeared inside the generated incident.

The Microsoft Defender incident graph displayed:

```text
SC200-WIN01
```

as an affected asset.

This improved the analyst investigation experience by linking the detection directly to the monitored endpoint.

---

## 14. Generating a Fresh Detection Event

After the analytics rule was enabled, a new encoded PowerShell event was intentionally generated.

The test payload was:

```powershell
$cmd = "Write-Output 'SC200-LAB-DETECTION-TEST'"
```

It was Base64 encoded:

```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
```

The encoded payload was then executed:

```powershell
powershell.exe -NoProfile -EncodedCommand $encoded
```

The command produced:

```text
SC200-LAB-DETECTION-TEST
```

The resulting Windows process-creation event was ingested into Microsoft Sentinel.

---

## 15. Incident Generation

The scheduled analytics rule detected the newly generated encoded PowerShell process.

A Microsoft Sentinel incident was automatically created:

```text
Suspicious PowerShell Command-Line Execution
```

The incident contained:

```text
Severity:
Medium

Status:
Active

Alerts:
1

Assets:
1

Affected Host:
SC200-WIN01
```

The incident graph correctly displayed the affected Windows host.

### Screenshot

```text
screenshots/07-powershell-incident.png
```

---

## 16. MITRE ATT&CK Mapping

The activity was mapped to:

```text
Tactic:
Execution
```

and:

```text
Technique:
T1059.001 — Command and Scripting Interpreter: PowerShell
```

PowerShell is a legitimate administrative technology but can also be used during malicious activity.

Therefore, detecting PowerShell execution should be based on additional context rather than the presence of `powershell.exe` alone.

---

## 17. Alert Investigation

The generated alert contained the relevant process information.

The investigation identified:

```text
Computer:
SC200-WIN01

Account:
SC200-WIN01\azureuser

Process:
powershell.exe

Detection Reason:
Encoded PowerShell command

EncodedCommand:
true

ExecutionPolicyBypass:
false
```

The full command line was also available.

This provided sufficient evidence to investigate what had actually been executed.

---

## 18. Process Context

Process ancestry is an important part of endpoint investigation.

The alert included:

```text
ParentProcessName
```

and:

```text
NewProcessName
```

This allows analysts to investigate the relationship between processes.

For example:

```text
explorer.exe
      ↓
powershell.exe
```

may indicate an interactive user execution.

A relationship such as:

```text
winword.exe
      ↓
powershell.exe
```

could require significantly greater investigation because Office applications launching PowerShell can be associated with malicious document behaviour.

Process ancestry should therefore be considered alongside:

- User account
- Command line
- Parent process
- Child process
- Host
- Time
- Additional telemetry

---

## 19. Encoded PowerShell Investigation

The command line showed that PowerShell had been executed using:

```text
-EncodedCommand
```

Encoded commands may be used legitimately, but they can also hide the actual command from immediate inspection.

The Base64 content therefore required further investigation.

Importantly, the encoded command was decoded rather than executed.

---

## 20. Decoding the PowerShell Payload

PowerShell `-EncodedCommand` commonly represents text encoded using UTF-16LE.

The Base64 value was extracted from the command line.

The following PowerShell command was then used to decode the payload:

```powershell
$encoded = "BASE64_VALUE"

[System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($encoded)
)
```

The decoded content was:

```powershell
Write-Output 'SC200-LAB-DETECTION-TEST'
```

This proved that the encoded command contained only the harmless test payload created during the lab.

### Screenshot

```text
screenshots/08-decoded-payload.png
```

---

## 21. Investigation Assessment

The incident investigation established the following:

```text
Encoded PowerShell execution:
Confirmed

Affected endpoint:
SC200-WIN01

Executing user:
azureuser

Process:
powershell.exe

EncodedCommand:
true

Decoded payload:
Write-Output 'SC200-LAB-DETECTION-TEST'

Malicious functionality:
None identified
```

The alert therefore represented a valid detection of suspicious-looking PowerShell behaviour, but the underlying activity was authorized security testing.

---

## 22. Analyst Conclusion

The following assessment was reached:

> Microsoft Sentinel detected PowerShell execution using the `-EncodedCommand` argument on `SC200-WIN01`.
>
> Windows Event ID 4688 provided visibility into the executing account, process, parent process, and command line.
>
> The encoded Base64 payload was extracted from the command line and decoded during investigation.
>
> The decoded command was `Write-Output 'SC200-LAB-DETECTION-TEST'`.
>
> No malicious functionality was identified in the decoded payload.
>
> The activity was intentionally generated as part of authorized security testing.
>
> The analytics rule operated as designed and successfully generated an alert and incident.

---

## 23. Incident Resolution

The incident was classified as expected security-testing activity.

The incident was resolved using:

```text
Status:
Resolved

Classification:
Informational, expected activity

Determination:
Confirmed activity / Security testing
```

No remediation was required because the PowerShell execution was intentionally generated.

---

## 24. Incident Closure Notes

The investigation could be documented using the following closure comment:

> Suspicious PowerShell execution was detected on SC200-WIN01 using the `-EncodedCommand` parameter. Event ID 4688 telemetry was reviewed and the encoded payload was decoded to `Write-Output 'SC200-LAB-DETECTION-TEST'`. No malicious functionality was identified. Activity was intentionally generated as part of an authorized Microsoft Sentinel detection lab. Detection logic operated as expected. No remediation required.

The incident was then moved from:

```text
New
```

to:

```text
Resolved
```

### Screenshot

```text
screenshots/09-incident-resolved.png
```

---

## 25. Investigation Findings

| Finding | Result |
|---|---|
| Monitored endpoint | `SC200-WIN01` |
| Windows Event ID | 4688 |
| Executing account | `azureuser` |
| Process | `powershell.exe` |
| Encoded command detected | Yes |
| Execution policy bypass detected | No for incident event |
| Command-line telemetry | Available |
| Encoded payload | Successfully decoded |
| Decoded command | `Write-Output 'SC200-LAB-DETECTION-TEST'` |
| Malicious functionality | None identified |
| Sentinel alert | Generated |
| Sentinel incident | Generated |
| Host entity mapping | Successful |
| Severity | Medium |
| MITRE ATT&CK | T1059.001 |
| Tactic | Execution |
| Classification | Informational, expected activity |
| Incident status | Resolved |

---

## 26. Key KQL Queries

### Review Windows Process Creation

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

### Hunt for PowerShell Execution

```kusto
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

### Hunt for Suspicious PowerShell Arguments

```kusto
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-EncodedCommand"
    or CommandLine contains "-ExecutionPolicy Bypass"
    or CommandLine contains "-NoProfile"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

### Enrich PowerShell Telemetry

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| extend
    EncodedCommand = CommandLine contains "-EncodedCommand"
        or CommandLine contains "-enc ",
    ExecutionPolicyBypass = CommandLine contains "-ExecutionPolicy Bypass",
    NoProfile = CommandLine contains "-NoProfile"
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    NewProcessName,
    EncodedCommand,
    ExecutionPolicyBypass,
    NoProfile,
    CommandLine
| order by TimeGenerated desc
```

### Encoded PowerShell Only

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-EncodedCommand"
    or CommandLine contains "-enc "
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine
| order by TimeGenerated desc
```

### Scheduled Detection Query

```kusto
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend
    EncodedCommand = CommandLine contains "-EncodedCommand"
        or CommandLine contains "-enc ",
    ExecutionPolicyBypass = CommandLine contains "-ExecutionPolicy Bypass"
| where EncodedCommand or ExecutionPolicyBypass
| extend DetectionReason = case(
    EncodedCommand, "Encoded PowerShell command",
    ExecutionPolicyBypass, "Execution policy bypass",
    "Suspicious PowerShell execution"
)
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    NewProcessName,
    DetectionReason,
    EncodedCommand,
    ExecutionPolicyBypass,
    CommandLine
```

---

## 27. SOC Investigation Workflow Demonstrated

This lab demonstrated the following investigation process:

```text
Alert received
      ↓
Validate detection
      ↓
Identify affected host
      ↓
Identify executing account
      ↓
Identify process
      ↓
Review parent process
      ↓
Review command line
      ↓
Identify encoded execution
      ↓
Extract encoded payload
      ↓
Decode payload safely
      ↓
Analyse decoded command
      ↓
Determine activity intent
      ↓
Map to MITRE ATT&CK
      ↓
Document findings
      ↓
Classify incident
      ↓
Resolve incident
```

---

## 28. Lessons Learned

### PowerShell Alone Is Not Malicious

PowerShell is widely used for legitimate administration and automation.

Therefore:

```text
powershell.exe executed
```

is not enough information to conclude that malicious activity occurred.

Additional context is required.

Useful indicators include:

- Encoded commands
- Execution-policy bypass
- Suspicious parent processes
- Download activity
- Obfuscated commands
- Unusual user accounts
- Unexpected hosts
- Network connections
- Process ancestry

---

### Command-Line Visibility Is Critical

Event ID 4688 originally showed process creation but did not contain command-line arguments.

Without command-line visibility, the analyst could see:

```text
powershell.exe
```

but could not determine how PowerShell had been invoked.

After enabling command-line auditing, Microsoft Sentinel could distinguish between:

```text
powershell.exe
```

and:

```text
powershell.exe -NoProfile -EncodedCommand ...
```

This significantly improved detection and investigation capability.

---

### `extend` Is Useful for Security Enrichment

KQL `extend` was used to transform raw command-line strings into useful security indicators.

For example:

```kusto
| extend EncodedCommand = CommandLine contains "-EncodedCommand"
```

converted a long command line into a simple Boolean field.

This makes large datasets easier to analyse and allows the same logic to be reused in detections.

---

### Encoded Commands Require Investigation, Not Assumptions

The use of Base64 encoding can make an execution suspicious.

However:

```text
Encoded ≠ Automatically malicious
```

The payload should be decoded and analysed.

In this lab, decoding revealed:

```powershell
Write-Output 'SC200-LAB-DETECTION-TEST'
```

which contained no malicious functionality.

---

### Decode Before Making a Verdict

The detection identified suspicious-looking behaviour.

The investigation established intent.

The workflow was:

```text
Encoded PowerShell detected
        ↓
Extract payload
        ↓
Decode payload
        ↓
Review command
        ↓
Determine behaviour
        ↓
Determine verdict
```

This prevents analysts from treating suspicious indicators as proof of compromise.

---

### Process Ancestry Matters

Parent-child process relationships can provide significant investigative context.

For example:

```text
explorer.exe
    ↓
powershell.exe
```

may be consistent with interactive execution.

However:

```text
winword.exe
    ↓
powershell.exe
```

could require further investigation.

The parent process should therefore be considered alongside the command line and executing account.

---

### Detection Rules Should Focus on Useful Signals

Alerting on every PowerShell execution would generate unnecessary noise.

Similarly, `-NoProfile` alone may be commonly used.

The rule therefore focused on stronger indicators:

```text
-EncodedCommand
```

and:

```text
-ExecutionPolicy Bypass
```

This demonstrates the importance of balancing visibility with detection quality.

---

### Entity Mapping Improves Investigation

Unlike the previous failed-logon lab, the host mapping worked correctly in this detection.

The incident graph displayed:

```text
SC200-WIN01
```

as an associated asset.

This demonstrates how entity mapping improves investigation context and allows analysts to pivot directly from an alert to an affected device.

---

### Detection Accuracy and Malicious Intent Are Different

The analytics rule correctly detected encoded PowerShell.

Therefore:

```text
Detection result:
Correct
```

The decoded command was harmless lab activity.

Therefore:

```text
Activity intent:
Benign / Authorized
```

A true security detection does not automatically mean that the underlying activity is malicious.

---

## 29. Skills Demonstrated

This project demonstrates practical experience with:

- Microsoft Sentinel
- Microsoft Defender
- Windows endpoint monitoring
- Azure Monitor Agent
- Data Collection Rules
- Log Analytics
- Windows Event ID 4688
- Process creation auditing
- Process command-line auditing
- PowerShell investigation
- Encoded PowerShell analysis
- Base64 analysis
- Kusto Query Language
- `where`
- `project`
- `extend`
- `case`
- Boolean detection logic
- Process ancestry analysis
- Detection engineering
- Scheduled analytics rules
- Alert enrichment
- Entity mapping
- MITRE ATT&CK mapping
- Alert generation
- Incident generation
- Incident triage
- Payload analysis
- Incident classification
- SOC documentation
- Incident resolution

---

## 30. Portfolio Evidence

```text
screenshots/
├── 01-4688-process-events.png
├── 02-commandline-enabled.png
├── 03-suspicious-powershell-hunt.png
├── 04-powershell-enrichment.png
├── 05-encoded-powershell.png
├── 06-analytics-rule-enabled.png
├── 07-powershell-incident.png
├── 08-decoded-payload.png
└── 09-incident-resolved.png
```

---

## 31. Final Result

This lab successfully demonstrated an end-to-end endpoint process-detection and incident-response workflow using Microsoft Sentinel.

Windows Event ID 4688 provided visibility into process creation activity on `SC200-WIN01`.

Process command-line auditing was enabled to enrich the telemetry with command-line arguments.

KQL was used to identify and classify suspicious-looking PowerShell execution.

A custom analytics rule was developed to detect PowerShell using:

```text
-EncodedCommand
```

or:

```text
-ExecutionPolicy Bypass
```

The rule successfully generated a Microsoft Sentinel alert and incident.

The incident contained an associated host entity, allowing `SC200-WIN01` to appear directly in the investigation graph.

The encoded Base64 payload was extracted and decoded during investigation.

The payload resolved to:

```powershell
Write-Output 'SC200-LAB-DETECTION-TEST'
```

No malicious functionality was identified.

The incident was classified as authorized security testing and resolved.

The final workflow was:

```text
SC200-WIN01
      ↓
PowerShell Execution
      ↓
Windows Event ID 4688
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
Log Analytics
      ↓
SecurityEvent
      ↓
KQL Hunting
      ↓
Suspicious PowerShell Detection
      ↓
Scheduled Analytics Rule
      ↓
Alert
      ↓
Incident
      ↓
Process Investigation
      ↓
Base64 Payload Decoding
      ↓
Analyst Assessment
      ↓
Classification
      ↓
Resolution
```

---

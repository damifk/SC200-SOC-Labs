# Lab 02 — Windows Failed Logon Detection & Incident Investigation with Microsoft Sentinel

## Overview

This lab demonstrates an end-to-end Microsoft Security Operations workflow using Microsoft Sentinel.

A Windows Server endpoint was deployed in Microsoft Azure and onboarded to Microsoft Sentinel using the Azure Monitor Agent (AMA) and a Data Collection Rule (DCR). Windows Security Event telemetry was collected into the `SecurityEvent` table and analysed using Kusto Query Language (KQL).

A controlled authentication scenario was then generated against a local Windows test account. Multiple failed logon attempts were deliberately created, followed by successful authentication.

The resulting Windows Event ID 4625 telemetry was investigated in Microsoft Sentinel. A custom KQL detection was developed and converted into a scheduled Microsoft Sentinel analytics rule.

The rule successfully generated alerts and incidents in Microsoft Defender. The incident was investigated, classified as authorized security testing, documented, and resolved.

The lab demonstrates the following workflow:

```text
Windows Endpoint
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
Log Analytics
      ↓
Microsoft Sentinel
      ↓
KQL Investigation
      ↓
Analytics Rule
      ↓
Alert
      ↓
Incident
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

- Deploy a Windows endpoint in Microsoft Azure
- Collect Windows Security Event telemetry using Azure Monitor Agent
- Configure a Data Collection Rule
- Send Windows Security Events into Microsoft Sentinel
- Query authentication activity using KQL
- Investigate failed Windows authentication attempts
- Understand Windows Event IDs 4624 and 4625
- Analyse authentication failure codes
- Build a threshold-based KQL detection
- Create a Microsoft Sentinel scheduled analytics rule
- Map the detection to MITRE ATT&CK
- Generate a Microsoft Sentinel alert
- Generate a Microsoft Sentinel incident
- Perform SOC-style incident triage
- Document investigation findings
- Classify and resolve the incident
- Tune the detection to reduce duplicate alerts
- Identify limitations in entity mapping and detection design

---

## Technologies Used

- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender
- Microsoft Defender portal
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Log Analytics
- Windows Server
- Windows Security Event Logs
- Kusto Query Language (KQL)
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
| Test Account | `SOC-LabUser` |

All activity was performed in an isolated and authorized security lab environment.

---

## Architecture

```text
┌────────────────────────────┐
│       SC200-WIN01          │
│       Windows Server       │
└─────────────┬──────────────┘
              │
              │ Windows Security Events
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
│  Log Analytics Workspace   │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│     Microsoft Sentinel     │
│                            │
│      SecurityEvent         │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│      KQL Investigation     │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│   Scheduled Analytics Rule │
│ Multiple Failed Logons     │
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
│   Investigation & Triage   │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│         Resolution         │
└────────────────────────────┘
```

---

## 1. Windows Endpoint Deployment

A Windows Server virtual machine named:

```text
SC200-WIN01
```

was deployed in Microsoft Azure.

The endpoint was configured without a directly exposed public IP address.

This reduced unnecessary public exposure while still allowing the VM to be used as a monitored Windows endpoint for the SOC lab.

---

## 2. Windows Security Event Collection

The **Windows Security Events via AMA** solution was installed in Microsoft Sentinel.

A Data Collection Rule was created and associated with `SC200-WIN01`.

The resulting collection pipeline was:

```text
SC200-WIN01
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
Log Analytics
      ↓
SecurityEvent
      ↓
Microsoft Sentinel
```

After the DCR was created, the **Windows Security Events via AMA** connector showed as connected.

---

## 3. Verifying Security Event Ingestion

The first step was to confirm that Windows Security Event telemetry was successfully reaching Microsoft Sentinel.

```kusto
SecurityEvent
| take 20
```

The query returned Windows Security Event records from:

```text
SC200-WIN01
```

This confirmed that the telemetry pipeline was operational.

### Screenshot

```text
screenshots/01-securityevent-ingestion.png
```

---

## 4. Reviewing Collected Windows Event IDs

The following KQL query was used to identify the Windows Security Event IDs being collected.

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize Events=count() by EventID
| order by Events desc
```

The environment returned several important Windows Security Event IDs.

| Event ID | Description |
|---|---|
| 4624 | Successful account logon |
| 4625 | Failed account logon |
| 4672 | Special privileges assigned to a new logon |
| 4673 | Privileged service called |
| 4688 | New process created |
| 4799 | Local security group membership enumerated |

Event ID `4625` became the primary focus of this investigation.

### Screenshot

```text
screenshots/02-eventid-summary.png
```

---

## 5. Authentication Test Scenario

A dedicated local Windows account was created for security testing:

```text
SOC-LabUser
```

The account was used to safely generate authentication telemetry.

Five incorrect passwords were deliberately supplied within a short period.

A valid password was then used afterwards.

The generated sequence was therefore:

```text
Failed authentication
Failed authentication
Failed authentication
Failed authentication
Failed authentication
        ↓
Successful authentication
```

From a SOC analyst perspective, repeated authentication failures followed by successful authentication can represent several possible scenarios:

- User password mistakes
- Password guessing
- Credential misuse
- Brute-force activity
- Automated authentication attempts
- Compromised credentials

In this case, the activity was intentionally generated as part of an authorized lab.

---

## 6. Investigating Failed Logons

The following KQL query was used to locate Windows Event ID 4625 events.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4625
| project
    TimeGenerated,
    Computer,
    Account,
    TargetAccount,
    LogonType,
    IpAddress,
    Activity
| order by TimeGenerated desc
```

Five failed authentication attempts were identified against:

```text
SC200-WIN01\SOC-LabUser
```

The events occurred on:

```text
SC200-WIN01
```

The events showed:

```text
LogonType: 2
IpAddress: ::1
```

`::1` represents the IPv6 loopback address, indicating that the authentication activity originated locally on the endpoint.

Logon Type `2` represents an interactive logon.

### Screenshot

```text
screenshots/03-failed-logons.png
```

---

## 7. Authentication Timeline Analysis

Successful and failed authentication events were reviewed together.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID in (4624, 4625)
| project
    TimeGenerated,
    EventID,
    Computer,
    Account,
    TargetAccount,
    LogonType,
    IpAddress
| order by TimeGenerated asc
```

The resulting sequence showed repeated failed authentication attempts followed by a successful authentication.

```text
4625  Failed
4625  Failed
4625  Failed
4625  Failed
4625  Failed
4624  Successful
```

In a production environment, this pattern would warrant investigation because repeated failures followed by a successful login could indicate that an attacker eventually obtained or guessed valid credentials.

In this lab, the sequence was intentionally generated.

---

## 8. Investigating Authentication Failure Codes

The failed authentication events were analysed further by reviewing the Windows status and substatus codes.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4625
| where TargetAccount has "SOC-LabUser"
| project
    TimeGenerated,
    Computer,
    TargetAccount,
    LogonType,
    IpAddress,
    FailureReason,
    Status,
    SubStatus
| order by TimeGenerated asc
```

The events contained:

```text
Status:    0xC000006D
SubStatus: 0xC000006A
```

The substatus value:

```text
0xC000006A
```

confirmed that the authentication attempts failed because an incorrect password was supplied.

This provided stronger evidence than simply observing Event ID 4625.

### Investigation Findings

| Field | Value |
|---|---|
| Event ID | 4625 |
| Computer | `SC200-WIN01` |
| Target Account | `SOC-LabUser` |
| Logon Type | 2 |
| Source Address | `::1` |
| Status | `0xC000006D` |
| SubStatus | `0xC000006A` |
| Failure Cause | Incorrect password |

### Screenshot

```text
screenshots/04-failure-reason.png
```

---

## 9. Building a Threshold-Based Detection

A KQL query was developed to identify accounts experiencing five or more failed authentication attempts.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4625
| summarize
    FailedAttempts=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated),
    SourceIPs=make_set(IpAddress),
    LogonTypes=make_set(LogonType)
    by Computer, TargetAccount
| where FailedAttempts >= 5
```

The query successfully returned the lab activity.

```text
Computer:       SC200-WIN01
TargetAccount:  SOC-LabUser
FailedAttempts: 5
Source IP:      ::1
Logon Type:     2
```

This demonstrated how KQL aggregation can transform individual authentication events into a meaningful security detection.

### Screenshot

```text
screenshots/05-threshold-detection.png
```

---

## 10. Detection Engineering

The KQL investigation was converted into a Microsoft Sentinel scheduled analytics rule.

### Analytics Rule Configuration

```text
Name:
Multiple Failed Windows Logons

Severity:
Medium

Category:
Credential Access

MITRE ATT&CK:
T1110 — Brute Force
```

The rule was designed to identify five or more failed authentication attempts against the same account.

The detection query was:

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated)
    by Computer, TargetAccount, IpAddress, LogonType
| where FailedAttempts >= 5
| extend TimeGenerated = LastFailure
```

The query preserved the following fields for alert enrichment:

```text
Computer
TargetAccount
IpAddress
LogonType
FailedAttempts
FirstFailure
LastFailure
```

---

## 11. Alert Custom Details

The following fields were configured as custom alert details:

```text
FailedAttempts
FirstFailure
LastFailure
LogonType
```

This allowed important investigation information to appear directly inside the alert.

The generated alert contained:

```text
Computer:       SC200-WIN01
TargetAccount:  SC200-WIN01\SOC-LabUser
IpAddress:      ::1
LogonType:      2
FailedAttempts: 5
```

This reduced the amount of manual querying required during initial triage.

### Screenshot

```text
screenshots/06-alert-evidence.png
```

---

## 12. MITRE ATT&CK Mapping

The detection was mapped to:

```text
Tactic:
Credential Access

Technique:
T1110 — Brute Force
```

The observed behaviour involved repeated password authentication attempts against the same account within a short period.

Although the activity in this lab was intentionally generated, the detection pattern can represent password guessing or brute-force activity in a real environment.

---

## 13. Analytics Rule Scheduling

The scheduled rule was configured to run periodically and inspect recent authentication telemetry.

Initial testing used a short query lookback window.

During troubleshooting, the lookback window was temporarily increased so that previously generated events remained available to the scheduled detection while the rule was being validated.

This demonstrated an important detection-engineering principle:

> A valid KQL query does not automatically mean that a scheduled detection will behave correctly.

Detection behaviour is also affected by:

- Query frequency
- Query lookback period
- Data ingestion delay
- Detection threshold
- Alert grouping
- Alert suppression
- Entity mapping
- Incident generation settings

---

## 14. Alert Generation

After the analytics rule was enabled, additional failed authentication attempts were generated.

The rule successfully identified the activity and generated a Microsoft Sentinel alert.

The alert showed:

```text
Rule:
Multiple Failed Windows Logons

Severity:
Medium

Category:
Credential Access

Detection Source:
Scheduled Detection

Service Source:
Microsoft Sentinel
```

This confirmed the following detection pipeline:

```text
Windows Security Event
      ↓
SecurityEvent
      ↓
KQL Detection
      ↓
Scheduled Analytics Rule
      ↓
Alert
```

---

## 15. Incident Generation

The alert automatically generated a Microsoft Sentinel incident.

The incident appeared in Microsoft Defender as:

```text
Multiple Failed Windows Logons
```

with:

```text
Severity:
Medium

Category:
Credential Access

MITRE ATT&CK:
T1110
```

This completed the full detection pipeline:

```text
SC200-WIN01
      ↓
Windows Security Events
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
SecurityEvent
      ↓
KQL
      ↓
Scheduled Analytics Rule
      ↓
Alert
      ↓
Incident
```

### Screenshot

```text
screenshots/07-incident-created.png
```

---

## 16. Incident Visibility Troubleshooting

Initially, it appeared that no incident had been created.

The following areas were checked:

- Analytics rule status
- Query scheduling
- Lookback period
- Alert threshold
- Rule execution
- Incident generation settings
- Telemetry availability

The detection logic was confirmed to be working.

The actual cause was an active filter on the Microsoft Defender Incidents page.

A priority score filter prevented the generated incidents from being displayed.

After removing the filter, the incidents became visible.

This resulted in an important SOC operational lesson:

> A missing incident does not necessarily mean that the detection failed.

Analysts should also verify:

- Incident filters
- Status filters
- Severity filters
- Priority filters
- Time ranges
- Workspace selection
- Alert queues

before modifying working detection logic.

---

## 17. Detection Tuning

During testing, multiple incidents were generated from the same authentication activity.

This happened because the same failed authentication events remained inside the analytics rule's lookback window across several scheduled executions.

For example:

```text
Five failed events occur
        ↓
Rule executes
        ↓
Detection matches
        ↓
Incident created
        ↓
Five minutes later
        ↓
The same five events are still inside the lookback window
        ↓
Detection matches again
        ↓
Another incident may be created
```

The rule therefore required tuning.

Alert grouping and suppression were introduced to reduce repeated incidents from the same activity.

This demonstrated a common detection-engineering challenge:

```text
Too sensitive
     ↓
Duplicate alerts
     ↓
Alert fatigue
     ↓
Increased analyst workload
```

Detection engineering therefore requires balancing visibility with operational usability.

---

## 18. Incident Investigation

The generated incident was opened in Microsoft Defender.

The associated alert contained the following evidence:

```text
Computer:
SC200-WIN01

Target Account:
SC200-WIN01\SOC-LabUser

Source Address:
::1

Logon Type:
2

Failed Attempts:
5
```

The alert matched the telemetry previously identified through manual KQL investigation.

This validated that the analytics rule successfully detected the intended authentication behaviour.

### Screenshot

```text
screenshots/08-alert-investigation.png
```

---

## 19. Analyst Assessment

The following assessment was made during investigation:

> Five failed interactive authentication attempts were detected against `SOC-LabUser` on `SC200-WIN01`.
>
> All failed attempts originated from the IPv6 loopback address `::1`, indicating that the authentication activity originated locally on the monitored endpoint.
>
> Windows Event ID 4625 telemetry was reviewed. Status `0xC000006D` and SubStatus `0xC000006A` confirmed that the authentication failures were caused by incorrect passwords.
>
> The failed authentication sequence was followed by successful authentication.
>
> The Microsoft Sentinel detection correctly identified the repeated authentication failures.
>
> The activity was intentionally generated as part of an authorized security lab. No evidence of unauthorized access was identified.

---

## 20. Incident Classification

Because the activity was deliberately generated for testing, the incident was classified as expected security testing.

The final incident state was:

```text
Status:
Resolved

Classification:
Informational, expected activity

Determination:
Security testing
```

This distinction is important.

The analytics rule correctly detected behaviour that matched its detection criteria.

Therefore, the detection itself was valid.

The underlying activity was simply authorized and expected.

---

## 21. Incident Closure Notes

The following closure comment was recorded:

> Five failed interactive logon attempts were detected against SOC-LabUser on SC200-WIN01, originating from the local loopback address ::1. Event 4625 telemetry confirmed incorrect-password failures, followed by a successful authentication. The activity was intentionally generated as part of an authorized SC-200/Sentinel lab. Detection logic functioned as expected. No remediation required.

The incident status was then changed from:

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

## 22. Detection Limitation Identified

One limitation was identified during the incident investigation.

Although the alert successfully contained fields such as:

```text
Computer
TargetAccount
IpAddress
```

the incident graph did not automatically display associated entities.

This indicates that the entity mappings in the analytics rule could be improved.

A future version of the rule could explicitly map:

```text
Host
Account
IP Address
```

to improve:

- Incident graphs
- Entity investigation
- Investigation pivots
- Context enrichment
- Analyst workflow

This represents a future detection-engineering improvement rather than a failure of the detection itself.

---

## 23. Key KQL Queries

### Verify Windows Security Event Ingestion

```kusto
SecurityEvent
| take 20
```

### Count Windows Security Event IDs

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize Events=count() by EventID
| order by Events desc
```

### Investigate Failed Logons

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4625
| project
    TimeGenerated,
    Computer,
    Account,
    TargetAccount,
    LogonType,
    IpAddress,
    Activity
| order by TimeGenerated desc
```

### Authentication Timeline

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID in (4624, 4625)
| project
    TimeGenerated,
    EventID,
    Computer,
    Account,
    TargetAccount,
    LogonType,
    IpAddress
| order by TimeGenerated asc
```

### Investigate Failure Codes

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4625
| where TargetAccount has "SOC-LabUser"
| project
    TimeGenerated,
    Computer,
    TargetAccount,
    LogonType,
    IpAddress,
    FailureReason,
    Status,
    SubStatus
| order by TimeGenerated asc
```

### Failed Authentication Threshold

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated),
    SourceIPs=make_set(IpAddress),
    LogonTypes=make_set(LogonType)
    by Computer, TargetAccount
| where FailedAttempts >= 5
```

### Scheduled Detection Query

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated)
    by Computer, TargetAccount, IpAddress, LogonType
| where FailedAttempts >= 5
| extend TimeGenerated = LastFailure
```

---

## 24. Investigation Findings

| Finding | Result |
|---|---|
| Monitored endpoint | `SC200-WIN01` |
| Target account | `SOC-LabUser` |
| Failed attempts | 5 |
| Windows Event ID | 4625 |
| Successful logon event | 4624 |
| Logon type | 2 |
| Source address | `::1` |
| Authentication status | `0xC000006D` |
| Authentication substatus | `0xC000006A` |
| Failure cause | Incorrect password |
| Sentinel alert | Generated |
| Sentinel incident | Generated |
| Severity | Medium |
| MITRE ATT&CK | T1110 — Brute Force |
| Classification | Informational, expected activity |
| Determination | Security testing |
| Incident status | Resolved |

---

## 25. SOC Investigation Workflow Demonstrated

This lab demonstrated the following investigation process:

```text
Alert received
      ↓
Validate detection
      ↓
Identify affected endpoint
      ↓
Identify affected account
      ↓
Review authentication telemetry
      ↓
Determine source
      ↓
Analyse Windows status codes
      ↓
Review successful authentication
      ↓
Determine activity scope
      ↓
Map behaviour to MITRE ATT&CK
      ↓
Determine analyst verdict
      ↓
Document findings
      ↓
Classify incident
      ↓
Resolve incident
```

---

## 26. Lessons Learned

### Telemetry Should Be Verified Before Detection Engineering

Before creating a detection, the required data must first be confirmed.

Running:

```kusto
SecurityEvent
| take 20
```

verified that Windows Security Events were arriving before detection logic was developed.

This reduced troubleshooting complexity.

---

### Windows Event IDs Provide Investigation Context

Windows Event IDs provide an important starting point for endpoint investigations.

Relevant examples from this lab included:

```text
4624 = Successful authentication
4625 = Failed authentication
4688 = Process creation
```

Understanding the event type helps determine the next investigative steps.

---

### Failure Codes Provide Additional Evidence

Event ID 4625 confirms that authentication failed.

The status and substatus fields explain why.

In this lab:

```text
Status:
0xC000006D

SubStatus:
0xC000006A
```

confirmed that an incorrect password was supplied.

Analysts should therefore inspect event details rather than relying only on the Event ID.

---

### Aggregation Converts Telemetry into Detection Logic

KQL aggregation functions were essential during this lab.

Functions used included:

```text
count()
min()
max()
make_set()
summarize
```

For example:

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts=count(),
    FirstFailure=min(TimeGenerated),
    LastFailure=max(TimeGenerated)
    by TargetAccount
```

transforms individual logon failures into a detection pattern.

---

### Investigation Queries and Detection Queries Have Different Goals

An investigation query is designed to help an analyst explore telemetry.

A detection query must also consider:

- Alert structure
- Scheduling
- Entity mapping
- Thresholds
- Grouping
- Suppression
- Incident generation

The lab demonstrated the difference between finding suspicious activity and operationalizing that query as a SIEM detection.

---

### Detection Logic and Detection Engineering Are Different

A KQL query can be technically correct while the resulting detection still requires tuning.

Important operational settings include:

```text
Query frequency
Lookback period
Threshold
Event grouping
Suppression
Entity mapping
Custom alert details
Incident generation
```

This lab demonstrated both KQL development and practical detection tuning.

---

### Portal Filters Can Affect SOC Investigations

The generated incidents initially appeared to be missing.

The cause was an active priority filter on the incident queue.

Once the filter was removed, the incidents became visible.

This demonstrated that analysts should confirm portal filters before assuming that a detection or incident pipeline has failed.

---

### Duplicate Alerts Require Tuning

The same set of authentication events generated multiple incidents because the events remained inside the scheduled query lookback window.

This produced repeated detections of the same underlying activity.

Alert grouping and suppression can help reduce duplicate incidents and analyst workload.

---

### Detection Accuracy and Malicious Intent Are Separate Questions

The analytics rule correctly detected repeated failed authentication attempts.

The underlying activity was authorized security testing.

Therefore:

```text
Detection = Correct

Activity = Benign / Expected
```

A valid security alert does not automatically mean that malicious activity occurred.

---

## 27. Skills Demonstrated

This project demonstrates practical experience with:

- Microsoft Sentinel
- Microsoft Defender
- Microsoft Azure
- Azure Monitor Agent
- Data Collection Rules
- Log Analytics
- Windows Security Event logging
- Windows Event ID analysis
- Kusto Query Language
- Authentication investigation
- Detection engineering
- Threshold-based detections
- Scheduled analytics rules
- Alert enrichment
- MITRE ATT&CK mapping
- Alert generation
- Incident generation
- Incident triage
- Incident classification
- SOC documentation
- Detection tuning
- Alert suppression
- Alert-fatigue reduction
- Root-cause analysis
- Security-event correlation

---

## 28. Portfolio Evidence

Recommended screenshots:

```text
screenshots/
├── 01-securityevent-ingestion.png
├── 02-eventid-summary.png
├── 03-failed-logons.png
├── 04-failure-reason.png
├── 05-threshold-detection.png
├── 06-analytics-rule.png
├── 07-incident-created.png
├── 08-alert-investigation.png
└── 09-incident-resolved.png
```

---

## 29. Final Result

This lab successfully demonstrated an end-to-end Microsoft security monitoring and incident-response workflow.

A Windows endpoint was onboarded into Microsoft Sentinel using Azure Monitor Agent and a Data Collection Rule.

Windows authentication telemetry was collected into the `SecurityEvent` table and investigated using KQL.

Repeated failed authentication attempts were generated and analysed.

A threshold-based KQL detection was developed and converted into a scheduled Microsoft Sentinel analytics rule.

The rule successfully generated alerts and incidents.

The resulting incident was investigated, mapped to MITRE ATT&CK T1110, documented, classified as authorized security testing, and resolved.

The final workflow was:

```text
SC200-WIN01
      ↓
Windows Security Events
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
Log Analytics
      ↓
Microsoft Sentinel
      ↓
SecurityEvent
      ↓
KQL Investigation
      ↓
Scheduled Analytics Rule
      ↓
Alert
      ↓
Incident
      ↓
SOC Investigation
      ↓
Classification
      ↓
Resolution
```

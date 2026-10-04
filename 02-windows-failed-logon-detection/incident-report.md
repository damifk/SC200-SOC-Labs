# Incident Report

## Incident
Multiple Failed Windows Logons

## Severity
Medium

## Category
Credential Access

## MITRE ATT&CK
T1110 – Brute Force

## Affected Host
SC200-WIN01

## Affected Account
SOC-LabUser

## Detection
Five failed Windows authentication attempts were observed within a short time period.

## Evidence
- Event ID 4625
- Logon Type 2
- Source IP ::1
- Status 0xC000006D
- SubStatus 0xC000006A
- Five failed attempts
- Successful authentication subsequently observed

## Analysis
The failed authentication attempts originated locally on SC200-WIN01. Windows telemetry confirmed that incorrect passwords caused the failures.

The activity matched the custom Microsoft Sentinel detection threshold and generated an incident.

## Verdict
True positive detection of expected security-testing activity.

## Resolution
No remediation required.

## Classification
Informational, expected activity.

## Determination
Security testing.

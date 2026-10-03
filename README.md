# SC200-SOC-Labs
# Microsoft Sentinel Deployment & Azure Activity Investigation

## Overview

This lab involved deploying a Microsoft Sentinel environment, ingesting Azure Activity logs into a Log Analytics workspace, and investigating Azure control-plane activity using Kusto Query Language (KQL).

The objective was to gain practical experience with Microsoft Sentinel architecture, Azure Activity ingestion, KQL investigation techniques, and security-event correlation while preparing for the Microsoft SC-200 certification.

## Environment

- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender portal
- Log Analytics
- Azure Activity Logs
- Azure Policy
- Kusto Query Language (KQL)

## Architecture

Azure Subscription
        |
        v
Azure Activity Log
        |
        v
Azure Policy / Diagnostic Settings
        |
        v
Log Analytics Workspace
        |
        v
Microsoft Sentinel
        |
        v
Advanced Hunting / KQL

## Lab Configuration

A dedicated resource group and Log Analytics workspace were created for the lab.

Microsoft Sentinel was enabled on the workspace and connected to the Microsoft Defender portal.

The Azure Activity solution was installed from the Sentinel Content Hub.

Azure Policy was then used to configure subscription-level Activity Logs to stream into the Log Analytics workspace.

## Investigation Scenario

Azure administrative activity was detected after configuring log ingestion.

The investigation aimed to determine:

- What operations occurred?
- Which identities performed the operations?
- Were any operations unsuccessful?
- Were the events related?
- What authorization permissions were involved?

## KQL Investigation

### Review Azure Activity

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    ActivityStatusValue,
    ActivitySubstatusValue,
    ResourceGroup
| order by TimeGenerated desc
```

### Activity by Caller

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| summarize Operations=count() by Caller
| order by Operations desc
```

### Activity by Operation

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| summarize Operations=count() by OperationNameValue
| order by Operations desc
```

### Failed Operations

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue =~ "Failure"
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    ActivityStatusValue,
    ResourceGroup
| order by TimeGenerated desc
```

### Correlation Analysis

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| summarize
    Events=count(),
    Operations=make_set(OperationNameValue),
    Statuses=make_set(ActivityStatusValue),
    Resources=make_set(ResourceId)
    by CorrelationId
| order by Events desc
```

### Authorization Analysis

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    ResourceId,
    CorrelationId,
    Authorization_d
| order by TimeGenerated asc
```

Findings
--------

Eight Azure Activity events were identified.

The primary operations observed were:

Operation    |    Events

Microsoft.Resources/deployments/write | 4

Microsoft.Authorization/policies/deployIfNotExists/action | 2

Microsoft.Insights/diagnosticSettings/write | 2

Two caller identifiers were observed.

Correlation analysis showed that all eight events shared the same CorrelationId, indicating that they formed part of the same Azure workflow.

No failed operations were detected.

Authorization analysis showed that deployment activity was performed using the Log Analytics Contributor role against a PolicyDeployment resource.

Assessment
----------

The observed activity was consistent with Azure Policy remediation used during configuration of Azure Activity ingestion into Microsoft Sentinel.

The combination of:

*   Policy deployment activity
    
*   DeployIfNotExists execution
    
*   Diagnostic settings creation
    
*   Shared correlation ID
    
*   Log Analytics Contributor authorization
    

supported the conclusion that the events represented expected administrative automation rather than malicious activity.

Conclusion
----------

This lab demonstrated an end-to-end Microsoft Sentinel workflow covering:

Azure telemetry collection → Log Analytics ingestion → KQL investigation → event correlation → authorization analysis → analyst assessment.

The exercise also demonstrated why individual log entries should not always be treated as independent events. CorrelationId analysis showed that multiple Azure Activity records represented different stages of one underlying workflow.

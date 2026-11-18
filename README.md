# Powershell-detection-Labs---MS-Sentinel



## 📌 Project Overview

This project focuses on detecting potentially suspicious PowerShell executions using Microsoft Sentinel.

The lab simulates PowerShell command execution on a Windows 10 virtual machine and monitors the activity through Windows Event Logs. PowerShell Script Block Logging is enabled to capture executed script content, which is collected by Azure Monitor Agent (AMA) and forwarded to Microsoft Sentinel using a Data Collection Rule (DCR).

A Scheduled Analytics Rule is then created in the Microsoft Defender portal to identify PowerShell executions containing suspicious command patterns and generate security incidents for investigation.

## 🎯 Objectives

- Enable PowerShell Script Block Logging on a Windows endpoint.
- Collect PowerShell execution logs (Event ID 4104).
- Configure Azure Monitor Agent and Data Collection Rules for log collection.
- Ingest Windows PowerShell Operational logs into Microsoft Sentinel.
- Create a Scheduled Analytics Rule to detect suspicious PowerShell commands.
- Generate security incidents based on detected activity.

## 🛠️ Lab Environment

| Component | Description |
|---|---|
| Host OS | Windows 11 |
| Virtualization | Oracle VirtualBox |
| Victim Machine | Windows 10 VM |
| Cloud Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| Log Collection | Azure Monitor Agent (AMA) |
| Log Configuration | Data Collection Rule (DCR) |
| Detection | Scheduled Analytics Rule |

## 🔄 Implementation Steps

### 1. Set Up the Windows Victim Machine

- Installed and configured Windows 10 as a virtual machine using Oracle VirtualBox.
- Used this VM as the endpoint for simulating PowerShell activity.
- Prepared the Azure environment by creating a Resource Group and Log Analytics Workspace.
- Set up Microsoft Sentinel using the Log Analytics Workspace.

### 2. Connect the Windows VM to Azure

- Onboarded the Windows 10 VM to Azure using Azure Arc.
- Installed Azure Monitor Agent (AMA).
- Created a Data Collection Endpoint (DCE) and Data Collection Rule (DCR).
- Configured the DCR to collect the `Microsoft-Windows-PowerShell/Operational` event log.
- Added the required Windows PowerShell event log configuration to the existing DCR.
- Checked heartbeat logs to confirm that the monitoring agent was communicating.

<img width="900" alt="image" src="https://github.com/user-attachments/assets/820eae66-23c2-48c4-bd5c-2752f5823527" /> 
<img width="900" alt="image" src="https://github.com/user-attachments/assets/ec50400d-54e0-45be-b2d3-45244fcf5f1d" />






### 3. Enable PowerShell Script Block Logging

Enabled Script Block Logging on the Windows 10 VM to capture PowerShell script execution details.

**PowerShell commands:**

Check the existing registry configuration:

```powershell
$regPath = "HKLM:\Software\Microsoft\Windows\Powershell\1\PowerShellEngine\ScriptBlockLogging"

Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
```

Create the registry key:

```powershell
New-Item -Path "HKLM:\Software\Microsoft\Windows\Powershell\1\PowershellEngine" -Name "ScriptBlockLogging" -Force
```

Enable Script Block Logging:

```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Powershell\1\PowershellEngine\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force
```

Verify the configuration:

```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Powershell\1\PowershellEngine\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
```


<img width="600" height="507" alt="image" src="https://github.com/user-attachments/assets/7ec1848c-0d3b-4016-a75c-f8cbe54f7243" />



### 4. Verify PowerShell Event Logging

After enabling Script Block Logging:

- Executed sample PowerShell commands on the Windows VM.
- Opened Windows Event Viewer.
- Navigated to:

`Applications and Services Logs → Microsoft → Windows → PowerShell → Operational`

- Verified whether the executed commands were being recorded.

**Event ID 4104 – Script Block Logging**

This event records PowerShell script block content and is used as the primary event source for this detection.

<img width="897" height="746" alt="image" src="https://github.com/user-attachments/assets/3f926e16-6be0-421f-902c-e22782aa9664" />



### 5. Create a Scheduled Analytics Rule

Navigated to the Microsoft Defender portal and created a Scheduled Analytics Rule to identify suspicious PowerShell execution patterns.

**Detection logic (KQL):**

```kql
Event
| where EventID == 4104
| where EventLog == "Microsoft-Windows-PowerShell/Operational"
| where EventData contains "Invoke-WebRequest"
    or EventData contains "IEX"
    or EventData contains "DownloadString"
| project TimeGenerated, Computer, EventID, EventData
```


**Detection criteria:**

The query looks for PowerShell Script Block Logging events containing:

- `Invoke-WebRequest` – Commonly used for making web requests and downloading content.
- `IEX` – Alias for Invoke-Expression, which executes a PowerShell expression or command.
- `DownloadString` – Method that can retrieve content from a specified URL.

Configured the rule to run on a scheduled basis and enabled incident creation so that matching detections could be generated as security incidents.

<img width="1912" height="1027" alt="image" src="https://github.com/user-attachments/assets/4a20a437-57b5-475e-9bc2-1c162dc41d75" />

<img width="1917" height="1025" alt="image" src="https://github.com/user-attachments/assets/f2279ba0-cfcf-491c-a4b9-f3a30742f98c" />




### 6. Simulate Suspicious PowerShell Activity

To test the detection rule, executed a simulated PowerShell command on the Windows 10 VM.

**Test command:**

```powershell
Invoke-Expression 'Write-Host "Simulated-Invoke-WebRequest"'
```

This command uses `Invoke-Expression` and includes the `Invoke-WebRequest` string in the executed script block.

The objective is to generate an Event ID 4104 record containing the detection keyword and test whether the configured analytics rule identifies it.


### 7. Verify Detection, Alert and Incident Generation

After executing the simulated PowerShell command:

- Navigated to the Microsoft Defender portal and checked the Alerts section.
- Verified that the Scheduled Analytics Rule successfully detected the simulated PowerShell activity and generated an alert.
- Opened the alert to review the detection details.
- Navigated to the Incidents section and verified the corresponding security incident.
- Reviewed the incident and manually closed it after completing the investigation.

**Result:** Successfully simulated PowerShell activity, detected it through Microsoft Sentinel, verified the generated alert and incident in Microsoft Defender, and completed the investigation by closing the incident.

<img width="1917" height="1035" alt="image" src="https://github.com/user-attachments/assets/83ca2185-8403-4efd-b7bc-69cf665a22c4" />


<img width="1917" height="1008" alt="image" src="https://github.com/user-attachments/assets/d172d4bc-e051-4f49-a471-080443beebdf" />



## 📊 Expected Detection Workflow

1. Execute the test PowerShell command on the Windows VM.
2. Windows records the script block through Event ID 4104.
3. Azure Monitor Agent collects the configured PowerShell Operational event logs.
4. The DCR forwards the collected logs to the Log Analytics Workspace.
5. Microsoft Sentinel evaluates the events using the Scheduled Analytics Rule.
6. Matching activity generates an alert and, when configured, a security incident.

## 📚 Skills Practiced

- Microsoft Sentinel configuration
- Microsoft Azure and Azure Arc
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Data Collection Endpoints (DCE)
- Windows Event Log Monitoring
- PowerShell Script Block Logging
- Kusto Query Language (KQL)
- Scheduled Analytics Rules
- Security Incident Generation
- Endpoint Monitoring and Detection

## ⚠️ Project Scope

This is a controlled home lab built for learning and practicing security monitoring and detection engineering.

The detection logic uses specific command strings as indicators. It is not intended to detect every form of malicious PowerShell execution.

## 🚀 Future Improvements

- Expand detection logic to identify additional suspicious PowerShell behaviours.
- Investigate detected events using Event ID 4104 details.
- Improve detection accuracy and reduce false positives.
- Explore automated incident response using Microsoft Sentinel Playbooks.

---

**Project Type:** SOC Home Lab / Detection Engineering  
**Platform:** Microsoft Sentinel | Microsoft Azure | Windows 10


👨‍💻 Author

Abhijith N V

Cybersecurity Researcher | SOC Analyst Aspirant

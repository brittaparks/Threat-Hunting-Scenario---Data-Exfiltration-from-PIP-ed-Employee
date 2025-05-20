# Threat-Hunting-Scenario---Data-Exfiltration-from-PIP-ed-Employee

## Scenario
An employee named **John Doe**, working in a sensitive department, was recently placed on a Performance Improvement Plan (PIP). After reacting poorly, management expressed concerns that John may attempt to steal proprietary information and resign.

John has **administrator access** on his device (`windows-target-1`) and is **not restricted in application usage**. It is suspected that he may **archive or compress data** and transfer it to an external/private destination.

---

## Timeline Summary and Findings

### Step 1: Search for Archive Activity
Initial query was run to find archived data:

```kql
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where FileName endswith ".zip"
| order by Timestamp desc
```
Finding: Regular creation of ZIP files observed under the path: C:\ProgramData\backup\

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/4cb8872b-aee2-4008-b7e8-70dd90ca23cf">


### Step 2: Investigating Associated Processes
Using a selected timestamp from the ZIP creation activity, the following query was run:

```kql
let specifictime = datetime(2025-05-20T20:49:47.7913592Z);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| order by Timestamp desc
| where Timestamp between ((specifictime - 2m) .. (specifictime + 2m))
| project Timestamp, FileName, ActionType, DeviceName, ProcessCommandLine
```
Finding: Around the same time, a PowerShell script silently installed 7-Zip and used it to archive employee data.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/ce57b6b8-34b0-48bd-ac40-19372bf135f5">


### Step 3: Investigating Possible Exfiltration

```kql
let specifictime = datetime(2025-05-20T20:49:47.7913592Z);
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| order by Timestamp desc
| where Timestamp between ((specifictime - 2m) .. (specifictime + 2m))
```
Finding: No evidence of network exfiltration was observed during the time of interest.

## Response

- Isolated the machine immediately  
- Relayed findings to the employee’s manager, including archive creations at regular intervals via PowerShell script  
- Noted that no evidence of data exfiltration was found, but highlighted the potential risk to the manager  


## MITRE ATT&CK Techniques

| Technique ID | Name                                               |
|--------------|----------------------------------------------------|
| T1059        | Command and Scripting Interpreter: PowerShell      |
| T1105        | Ingress Tool Transfer                              |
| T1560        | Archive Collected Data: Archive via Utility        |

## Recommendations

- Create an alert to notify of silent installations via PowerShell script  
- Install a Data Loss Prevention (DLP) solution  
- Restrict employees from archiving data  


## Analyst Contact

**Name**: Britt Parks  
**Contact**: [linkedin.com/in/brittaparks](https://linkedin.com/in/brittaparks)  
**Date**: May 20, 2025


---
description: >-
  MITRE ATT&CK™  Process Discovery & System Service Discovery  - Technique T1057
  & T1007
---

# Processes & Services

## Theory

This page provides useful commands for Windows enumeration that can be used to query process and services information.

## Practice

### Services

{% hint style="danger" %}
When using a network logon like WinRM or a bind shell, use of `Get-CimInstance` or `Get-Service` with a non-administrative user leads to a "permission denied". However, employing an interactive logon, such as RDP, resolves this issue.
{% endhint %}

{% tabs %}
{% tab title="CMD" %}
To obtain a list of all the services, we can use one of the following commands

```powershell
#Net command
net start

#WMI
wmic service list brief
wmic service get name,displayname,pathname,startmode

#sc.exe
sc.exe query state= all
```
{% endtab %}

{% tab title="PowerShell" %}
To obtain a list of all the services, we can use one of the following commands

```powershell
# WMI
## Basic Usage
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
## Running Services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# WMI Wrapper
## Basic Usage
Get-Service
## Running Services
Get-Service | Where-Object {$_.Status -eq "Running"}
```
{% endtab %}
{% endtabs %}

### Processes

{% tabs %}
{% tab title="CMD" %}
To obtain a list of all processes, we can use one of the following commands

```powershell
# WMI
## wmic.exe
wmic process list brief
wmic process get name,executablepath,processid
wmic process get processid,commandline 
#Get commandline for a given process
wmic process where processid="2484" get name,commandline,processid

# TaskList
tasklist /V
## Display services hosted in each process
tasklist /SVC
## Display detailled information for process not running as SYSTEM
tasklist /FI "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running" /V
```
{% endtab %}

{% tab title="PowerShell" %}
```powershell
# WMI Wrapper
## Basic Usage
Get-Process

## By name + print all attributes
Get-Process winword | Format-List *
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1007/" %}

{% embed url="https://attack.mitre.org/techniques/T1057/" %}

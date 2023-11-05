# Processes & Services

## Theory

This page provides useful commands for Windows enumeration that can be used to query process and services informations.

## Practice

### Services

To obtain a list of all the services, we can use one of the following commands

{% tabs %}
{% tab title="Enumerate" %}
```powershell
#Net command
net start

#WMI
wmic service list brief
wmic service get name,displayname,pathname,startmode

#sc.exe
sc.exe query state= all

#Powershell
Get-Service
```
{% endtab %}
{% endtabs %}

### Processes

{% tabs %}
{% tab title="Enumerate" %}
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

#Powershell
Get-Process
```
{% endtab %}
{% endtabs %}

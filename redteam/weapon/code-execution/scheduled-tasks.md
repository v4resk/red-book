---
description: MITRE ATT&CK™  Scheduled Task/Job  - Technique T1053.002
---

# Scheduled Tasks

## Theory

Windows scheduled tasks can also be leveraged to run arbitrary commands since they execute a command when started.&#x20;

## Practice

{% tabs %}
{% tab title="schtasks.exe" %}
On windows, we can use the built in schtasks.exe binary to remotely interact with services

```bash
#Create a Task
schtasks /RU "SYSTEM" /create /tn "MyTask" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

#Run It 
schtasks /run /TN "MyTask" 

#Delete a Task
schtasks /TN "MyTask" /DELETE /F
```
{% endtab %}
{% endtabs %}

You may want to check this page for remote scheduled tasks execution :

{% content-ref url="../../pivoting/scheduled-tasks-atsvc.md" %}
[scheduled-tasks-atsvc.md](../../pivoting/scheduled-tasks-atsvc.md)
{% endcontent-ref %}

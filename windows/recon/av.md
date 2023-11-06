---
description: >-
  MITRE ATT&CK™ Software Discovery: Security Software Discovery - Technique
  T1518.001
---

# Security Solutions

## Theory

It is important to enumerate antivirus and security detection methods on an endpoint in order to stay as undetected as possible and reduce the chance of getting caught. We will see various techniques to enumerate the target's security solutions.

## Practice

{% tabs %}
{% tab title="AntiVirus" %}
We can enumerate AV software using Windows built-in tools, such as `wmic`

```powershell
#CMD
PS C:\Users\v4resk> wmic /namespace:\\root\securitycenter2 path antivirusproduct

#PowerShell cmdlet
PS C:\Users\v4resk> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```
{% endtab %}

{% tab title="Defenders" %}
We can enumerate if Windows Defender is running:

```powershell
#Check if running
PS C:\Users\v4resk>  Get-Service WinDefend
```

Next, we can start using the Get-MpComputerStatus cmdlet to get the current Windows Defender status.

```powershell
#PowerShell cmdlet
PS C:\Users\v4resk> Get-MpComputerStatus
PS C:\Users\v4resk> Get-MpComputerStatus | select RealTimeProtectionEnabled
```

We can try to disable it using the Set-MpPreference cmdlet.

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

{% hint style="info" %}
We need Admin privileges in order to modify Defender properties
{% endhint %}
{% endtab %}

{% tab title="FireWalls" %}
We can enumerate the `Windows Firewall` software with powershell.

```powershell
#Enum if its enabled
PS C:\Users\v4resk> Get-NetFirewallProfile
PS C:\Users\v4resk> Get-NetFirewallProfile | Format-Table Name, Enabled

#Enum rules
PS C:\Users\v4resk> Get-NetFirewallRule | findstr "Rule-Name"
```

We can try to disable it using the Set-NetFirewallProfile cmdlet.

```powershell
PS C:\Users\v4resk> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
```

We can now use built-in windows tools to test connections:

```powershell
PS C:\Users\v4resk> Test-NetConnection -ComputerName 127.0.0.1 -Port 80
PS C:\Users\v4resk> (New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected
```

{% hint style="info" %}
We need Admin privileges in order to modify NetFirewall properties
{% endhint %}
{% endtab %}

{% tab title="Sysmon" %}
[Sysmon (System Monitor)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.\
To detect sysmon on a target we can do:

```powershell
# With process list
PS C:\Users\v4resk> Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }

# With services list
PS C:\Users\v4resk> Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
PS C:\Users\v4resk> Get-Service | where-object {$_.DisplayName -like "*sysm*"}

#Windows Registry

PS C:\Users\v4resk> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```

If the target system is running Sysmon, we must try to locate its configuration file

```bash
findstr /si '<ProcessCreate onmatch="exclude">' C:\*
```
{% endtab %}

{% tab title="EDRs" %}
We can use scripts for enumerating security products within the machine, such as [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker).

```powershell
PS C:\Users\v4resk> Invoke-EDRChecker
```
{% endtab %}

{% tab title="AppLocker" %}
Discover the AppLocker policies. You may need to retrieve the AppLocker policy based on its unique LDAP path as shown the last example.

```powershell
#CMD
C:\> reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe\

#Powershell
PS C:\> (Get-AppLockerPolicy -Local).RuleCollections
PS C:\> Get-AppLockerPolicy -Effective -Xml
PS C:\> Get-ChildItem -Path HKLM:Software\Policies\Microsoft\Windows\SrpV2 -Recurse
PS C:\> Get-AppLockerPolicy -Domain -LDAP "LDAP:// DC13.Contoso.com/CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=Contoso,DC=com
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/thelayoftheland" %}

{% embed url="https://attack.mitre.org/techniques/T1518/001/" %}

# Enum Security Solutions

## Theory

It is important to enumerate antivirus and security detection methods on an endpoint in order to stay as undetected as possible and reduce the chance of getting caught. We will see various techniques to enumerate the target's security solutions.

## Practice

{% tabs %}
{% tab title="AntiVirus" %}

We can enumerate AV software using Windows built-in tools, such as `wmic`

```bash
#CMD
PS C:\Users\v4resk> wmic /namespace:\\root\securitycenter2 path antivirusproduct

#PowerShell cmdlet
PS C:\Users\v4resk> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```
{% endtab %}

{% tab title="Defenders" %}

We can enumerate if Windows Defender is running: 
```bash
#Check if running
PS C:\Users\v4resk>  Get-Service WinDefend
```
Next, we can start using the Get-MpComputerStatus cmdlet to get the current Windows Defender status. 
```bash
#PowerShell cmdlet
PS C:\Users\v4resk> Get-MpComputerStatus
PS C:\Users\v4resk> Get-MpComputerStatus | select RealTimeProtectionEnabled
```
{% endtab %}
{% tab title="FireWalls" %}

We can enumerate the `Windows Firewall` software with powershell.

```bash
#Enum if its enabled
PS C:\Users\v4resk> Get-NetFirewallProfile
PS C:\Users\v4resk> Get-NetFirewallProfile | Format-Table Name, Enabled

#Enum rules
PS C:\Users\v4resk> Get-NetFirewallRule | findstr "Rule-Name"
```

We can try to disable it using the Set-NetFirewallProfile cmdlet.
 
``` bash
PS C:\Users\v4resk> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
```

We can now use built-in windows tools to test connections:
```bash
PS C:\Users\v4resk> Test-NetConnection -ComputerName 127.0.0.1 -Port 80
PS C:\Users\v4resk> (New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected
```
{% hint style="info" %}
We need Admin privileges in order to modify NetFirewall properties
{% endhint %} 
{% endtab %}

{% tab title="Sysmon" %}
[Sysmon (System Monitor)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.  
To detect sysmon on a target we can do:
```bash
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


{% endtabs %}


## Resources

{% embed url="https://tryhackme.com/room/thelayoftheland" %}




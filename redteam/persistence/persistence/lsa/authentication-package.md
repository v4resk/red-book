---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Authentication Package -
  Technique T1547.002
---

# Authentication Package

## Theory

We may abuse [authentication packages](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-packages) to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.

## Practice

{% hint style="danger" %}
We won't be able to make it work If [LSA protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#enable-by-using-the-registry) is enabled as LSASS.exe will run as a [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process).
{% endhint %}

Authentication packages can be seen under following registry, and the referenced DLLs are then executed by the system when the authentication packages are loaded.

* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`

{% tabs %}
{% tab title="Authentication Packages" %}
First, you will have to copy the malicious package.dll in System32

```powershell
copy "$PathToDll\package.dll" C:\Windows\System32\
```

Then, edit LSA registry keys to include the new authentication package

```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\0package.dll" /f
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1547/002/" %}

---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Authentication Package -
  Technique T1547.002
---

# 🛠️ Authentication Package

## Theory

We may abuse [authentication packages](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-packages) to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.

## Practice

{% hint style="danger" %}
We won't be able to make it work If [LSA protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#enable-by-using-the-registry) is enabled as LSASS.exe will run as a [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process).
{% endhint %}

{% tabs %}
{% tab title="Authentication Packages" %}
Authentication packages can be seen under following registry, and the referenced binaries are then executed by the system when the authentication packages are loaded.

* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`

```
// Some code
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1547/002/" %}

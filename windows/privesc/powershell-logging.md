---
description: MITRE ATT&CK™  Unsecured Credentials - Technique T1552
---

# PowerShell Logging

## Theory

In enterprise environments, we will often find PowerShell logging mechanisms enabled as Powershell tends to be an attractive attack surface. Although these are defensive measures, we may take advantage of them.

The **PowerShell command history**, **PowerShell transcription** or **PowerShell script block Logging** may contain valuable information such as credentials, configuration settings, sensitive information that may be used as a means of privilege escalation.

* **PowerShell Transcript**: creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session. The information is stored in transcript files, which are by default written to the user’s documents folders, but can be configured to any accessible location on the local system or on the network.
* **PowerShell Script Block Logging**: captures commands and script blocks as events during execution, significantly expanding the scope of logged information by recording the complete content of executed code and commands. Consequently, each recorded event includes the original representation of encoded code or commands.
* **PowerShell Command History**: enabled by default, from PowerShell v5 on Windows 10, it saves the history of user's PowerShell sessions in a file. This file does not record non-terminal PowerShell sessions (such as WinRM or reverse shells).

## Practice

### PowerShell Command History

{% tabs %}
{% tab title="Command History" %}
You should always first check the Command History File before checking other registration mechanisms. It contains user's commands logged by the [PSReadline](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about\_psreadline?view=powershell-7.3) module

```powershell
# Check for ConsoleHost_history.txt location
(Get-PSReadlineOption).HistorySavePath

# Print ConsoleHost_history.txt (default location)
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\<USERNAME>\AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

We may also check the `Get-History` cmdlet, but its contents may be deleted by administrators using `Clear-History`. Note that `Clear-History` does not clear the command history recorded by PSReadline.

```powershell
Get-History
```
{% endtab %}
{% endtabs %}

### **PowerShell Transcription**

{% tabs %}
{% tab title="Transcription" %}
PowerShell transcripts are automatically named to prevent collisions, with names beginning with `PowerShell_transcript`. By default, transcripts are written to the user’s documents folder.

Thus, we can simply check files in user's folder or search for specific filenames on the target computer.

```powershell
# Search for transcription in Documents folder
dir $env:userprofile\Documents
dir C:\Users\<USERNAME>\Documents

# Search transcription by filename
Get-ChildItem -Path C:\ -Include *transcript* -File -Recurse -ErrorAction SilentlyContinue
dir /s /b C:\*transcript*
```
{% endtab %}
{% endtabs %}

### **PowerShell Script Block Logging**

{% tabs %}
{% tab title="Script Block Logging" %}
Script block logging events are recorded using Windows EventID 4104. We may use following command to see them

```powershell
# Basic check
## print all events
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104|fl
## print first event
(Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104)[0]|fl

# Print events while a private key is required (you must have this key)
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104|Unprotect-CmsMessage|fl
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.mandiant.com/resources/blog/greater-visibility" %}

{% embed url="https://attack.mitre.org/techniques/T1552/" %}

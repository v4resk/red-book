---
description: >-
  MITRE ATT&CK™  Remote Services: Windows Remote Management   - Technique
  T1021.006
---

# WinRM

## Theory

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the `winrm` command or by any number of programs such as PowerShell. WinRM can be used as a method of remotely interacting with [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047).

## Practice

### Execute Remote Commands

{% tabs %}
{% tab title="UNIX-like" %}
We can use [netexec](https://github.com/mpgn/NetExec) to remotely execute a command on the target over WinRM.

```bash
#Execute command
netexec winrm <IP> -u <user> -p <password> -x "whoami"

#Execute PowerShell command
netexec winrm <IP> -u <user> -p <password> -x "$(Get-WMIObject -class Win32_ComputerSystem | select username).username"
```
{% endtab %}

{% tab title="Windows" %}
We can use the PowerShell `Invoke-Command` cmdlet to remotely execute a command on the target over WinRM.

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

{% tab title="Windows" %}
We can use Powershell's `Enter-PSSession` cmdlet to start an interactive session with a remote computer.

```powershell
#Create Powershell PSCredential object
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

# Start a remote powershell session
Enter-PSSession -ComputerName <TARGET> -Credential $credential
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1021/006/" %}

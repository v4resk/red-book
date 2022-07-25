---
description: MITRE ATT&CK™ Sub-techniques T1558.001 and T1558.002
---

# Pivoting in Active Directory

## Theory

In a red team assesment you will have to pivot throught the network. You will find here some technics about that like

* **Spawn a process remotly**: with PsExec, WinRM, SC (Services), Scheduled Tasks 
* **WMI & Lateral Movement**: allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement
* **Alternate Authentication Material**: like NTLM or Kerberos Authentication


## Practice

### Spawn a process remotly
In this part, you will see various techniques, tools, for Active Directory enumeration. But you will consider that you already have compromise a initial account in the AD. 

#### PsExec

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) can exec a remote process.

```bash
psexec.py username:password@10.10.10.10 cmd.exe
```
{% endtab %}

{% tab title="Windows" %}
Psexec is one of many Sysinternals Tools and can be downloaded [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), It connect to the $ADMIN shares with SMB and upload a service binary. Psexec uses psexesvc.exe as the name. Then it connect to the service control manager to create and run a service named PSEXESVC associated with the previous binary. Finally Psexec create some named pipes to handle stdin/stdout/stderr.

```bash
#Run PsExec
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
```

{% endtab %}
{% endtabs %}

#### WinRm

Windows Remote Management (WinRM) is a web-based protocol used to send Powershell commands to Windows hosts remotely. Most Windows Server installations will have WinRM enabled by default, making it an attractive attack vector.

{% tabs %}
{% tab title="UNIX-like" %}
The [Evil-WinRm](https://github.com/Hackplayers/evil-winrm) can be used to obtain a winrm powershell session

```bash
evil-winrm -u user -p password -i 10.10.10.10
```
{% endtab %}

{% tab title="Windows" %}

We can use the WinRs binary

```bash
#Winrm Binary
winrs.exe -u:Administrator -p:Mypass123 -r:10.10.10.10 cmd
```
Or we can do the same with PowerShell

```bash
#Winrm Binary
#With PowerShell and PSCredential object
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

#Now we can create an interactive session or Invoke-Command remotly
#Interactive Session
Enter-PSSession -Computername TARGET -Credential $credential

#Invoke command remotly
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

{% endtab %}
{% endtabs %}

### WMI & Lateral Movement



## References

{% embed url="https://tryhackme.com/room/lateralmovementandpivoting" %}

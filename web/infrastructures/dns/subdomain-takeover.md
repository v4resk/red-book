---
description: 'OWASP: WSTG-CONF-10'
---

# Subdomain Takeover

## Theory&#x20;

A subdomain takeover occurs when an attacker gains control over a subdomain of a target domain. Typically, this happens when the victim’s external DNS server subdomain record is configured to point to a non-existing or non-active resource/external service/endpoint.

If the subdomain takeover is successful, a wide variety of attacks are possible (serving malicious content, phishing, stealing user session cookies, credentials, etc.). This vulnerability could be exploited for a wide variety of DNS resource records including: `A`, `CNAME`, `MX`, `NS`, `TXT` etc. In terms of the attack severity, an `NS` subdomain takeover (although less likely) has the highest impact, because a successful attack could result in full control over the whole DNS zone and the victim’s domain.

## Practice

### Enumerate

Before attempting a domain or subdomain takeover, it's crucial to enumerate all subdomains associated with the target domain. Refer to the below section for comprehensive techniques and tools.

{% content-ref url="../../recon/subdomain-enum.md" %}
[subdomain-enum.md](../../recon/subdomain-enum.md)
{% endcontent-ref %}

### Scanning for Subdomain Takeover

After enumerating subdomains, we can use these tools to perform a Subdomain Takeover scan and detect any subdomains that might be vulnerable.

{% tabs %}
{% tab title="Subzy" %}
[Subzy](https://github.com/PentestPad/subzy) (Golang) is a subdomain takeover vulnerability checker which works based on matching response fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md).

We can use this tools and scan for each subdomain discovered.

```bash
# Scan a list of subdomains
subzy run --targets domains.txt

# Scan for a single subdomain
subzy run --target test.example.com

# One-liner: find subdmains + scan for domain takeover
echo 'example.com'|(subfinder -all||assetfinder -subs-only)|uniq -u > domains.txt;subzy r --targets domains.txt | sed 's/\x1b\[[0-9;]*m//g' |grep -iE -A 2 "\[ VULNERABLE"
```
{% endtab %}

{% tab title="httpx" %}
We may use [httpx](https://github.com/projectdiscovery/httpx) for checking HTTP response status for each subdomain discovered.

```bash
# -title: Display page title
# -wc: Display response body word count
# -sc: Display response status-code
# -cl: Display response content-length
# -ct: Display response content-type
# -location: Display response redirect location
# -web-server: Display server name
# -asn: Display host ASN information
# -o: Output
cat domains.txt | httpx -title -wc -sc -cl -ct -location -web-server -asn -o alive-subdomains.txt

# Resume Scan (-resume)
# You can resume the scan using `resume.cfg`.
cat domains.txt | httpx -title -wc -sc -cl -ct -location -web-server -asn -o alive-subdomains.txt -resume resume.cfg
```

The, we can then check for error codes 404 and check on [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) if the provider allows us to register subdomains.
{% endtab %}

{% tab title="TakeOver.py" %}
[Takeover.py](https://github.com/edoardottt/takeover/) (python) is a subdomain takeover vulnerability checker.

```bash
# Scan a list of subdomains
python3 takeover.py -l domains.txt
```
{% endtab %}

{% tab title="SubdOver" %}
[Subdover](https://github.com/PushpenderIndia/subdover) (python) is a subdomain takeover vulnerability scanner, which has more than 88+ fingerprints of potentially vulnerable services.

```bash
# From list
python3 subdover.py -l domains.txt

# Single domain (will scan for subdomains using findomain)
python3 subdover.py -d example.com
```
{% endtab %}

{% tab title="SubOver" %}
[SubOver](https://github.com/Ice3man543/SubOver) (Golang) can be used to detect potential subdomain takeovers by checking a list of subdomains.

```bash
SubOver -l domains.txt
```
{% endtab %}
{% endtabs %}

### Subdomain Takeover

{% tabs %}
{% tab title="CNAME Record" %}
#### Identify Misconfigurations for Subdomains

First, check DNS records for identifying what’s on the destination of the subdomain.

```bash
dig sub.example.com ANY
dig sub.example.com CNAME
```

If the HEADER status is **NXDOMAIN** error in the result, subdomain takeover might be possible.\
Also we can try to access them with web browser or command-line:

```bash
# -L: Follow redirect
# -v: Verbose mode
curl -Lv app.example.com
curl -v cloud.example.com
curl -v mail.example.com
```

#### Spoof with the Subdomain

If a certain subdomain can be accessible but the error page of the specific provider (e.g. GitHub, Google Cloud, Wix, etc.) appeared, it means that the subdomain of the settings in the service provider was removed but the DNS record (e.g. A, CNAME) remains yet.

In short, attackers can spoof as a legitimate site by claiming this subdomain in the provider.

Here’s an abstract example:

1. Login the target provider.
2. Create a malicious website.
3. Add the target subdomain (e.g. app.example.com) as custom domain in the setting page.
4. If users visit app.example.com, they have now visited a malicious website created by an attacker.
{% endtab %}

{% tab title="NS Record" %}
It’s more dangerous If NS record is vulnerable because if the nameserver is taken over, an attacker can take full control of victim’s domains.

To gather NS records for the target domain, use `dig` command.

```
dig example.com +short NS

# Result examples
ns-100.abcde.org
ns-120.abcde.co.uk
```

Next, check if the gathered domains can be purchased with domain name registrar like GoDaddy, NameCheap.

For example, search `[abcde.org](http://abcde.org)` in the domain search page of NameCheap. If this domain can be purchased, attackers can buy this domain then take control the name resolution of a victim by creating the custom nameserver which pointed to this domain.
{% endtab %}

{% tab title="DNS Wildcard" %}
When DNS wildcard is used in a domain, any requested subdomain of that domain that doesn't have a different address explicitly will be **resolved to the same information**. This could be an A ip address, a CNAME...

For example, if `*.testing.com` is wildcarded to `1.1.1.1`. Then, `not-existent.testing.com` will be pointing to `1.1.1.1`.

However, if instead of pointing to an IP address, the sysadmin points it to a **third party service via CNAME**, like a G**ithub subdomain** for example (`sohomdatta1.github.io`). An attacker could **create his own third party page** (in Gihub in this case) and say that `something.testing.com` is pointing there. Because, the **CNAME wildcard** will agree the attacker will be able to **generate arbitrary subdomains for the domain of the victim pointing to his pages**.

You can find an example of this vulnerability in the CTF write-up: [https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api)
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover" %}

{% embed url="https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover" %}

{% embed url="https://exploit-notes.hdks.org/exploit/reconnaissance/subdomain/subdomain-takeover/" %}

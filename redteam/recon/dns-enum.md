---
description: 'MITRE ATT&CK™  Gather Victim Network Information: DNS - T1590.002'
---

# DNS Enumeration

## Theory

Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS, MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk.

Each domain can use different types of DNS records. Some of the most common types of DNS records include:

* **NS**: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
* **A**: Also known as a host record, the "_a record_" contains the IPv4 address of a hostname (such as www.megacorpone.com).
* **AAAA**: Also known as a quad A host record, the "_aaaa record_" contains the IPv6 address of a hostname (such as www.megacorpone.com).
* **MX**: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
* **PTR**: Pointer Records are used in reverse lookup zones and can find the records associated with an IP address.
* **CNAME**: Canonical Name Records are used to create aliases for other host records.
* **TXT**: Text records can contain any arbitrary data and be used for various purposes, such as domain ownership verification.

## Practice

{% tabs %}
{% tab title="Dig" %}
The dig (domain information groper) command is a flexible tool for interrogating DNS name servers. It performs DNS lookups and displays the answers that are returned from the queried name server(s).

```bash
# Simple DNS resolution
dig domain.com

#Enum records
dig MX domain.com
dig NS domain.com
dig A domain.com
dig txt domain.com
dig AAAA domain.com

#If supported by the DNS server, we can use the ANY query and dump all records
dig any domain.com

#Zone transfert
dig axfr domain.com @ns.domain.com
```
{% endtab %}

{% tab title="Host" %}
Using the host command, we may perform DNS and revers DNS enumeration

```bash
# Simple DNS resolution
host domain.com

# Enum records
host -t MX www.domain.com
host -t NS domain.com
host -t A domain.com
host -t txt domain.com
host -t AAAA domain.com

# Reverse DNS
# Works if the DNS is configured with a PTR record
host 149.56.244.87

# Bash script reverse DNS lookup an IP addresses range
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```
{% endtab %}

{% tab title="Nslookup" %}
Nslookup is a native **Windows & Linux** command that may be used as a [LOLBAS](../evasion/living-off-the-land/lolbas.md) to perform DNS enumeration

```powershell
# Simple DNS resolution
nslookup domain.com

# Enum records, you may use set=all
nslookup
> set type=ns
> domain.com

# Specify a DNS server
nslookup
> server 10.10.10.8
> domain.com

# One-liner: request TXT records for info.domain.com on 10.10.10.8 DNS server
nslookup -type=TXT info.domain.com 10.10.10.8 

# Reverse DNS
# Works if the DNS is configured with a PTR record
nslookup 149.56.244.87
```
{% endtab %}

{% tab title="DNSRecon" %}
[DNSRecon](https://github.com/darkoperator/dnsrecon) is a Python script that provides the ability to perform DNS enumeration.

```bash
#Basic enum
dnsrecon -d domain.com
# -t std for standar scan
dnsrecon -d domain.com -t std

#Brute force domains and hosts
dnsrecon -t brt -d domain.com -D /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt

#Bing (-b) and yandex (-y) search enum
dnsrecon -by -d domain.com

#Zone transfert
dnsrecon -a -d domain.com

#DNSSEC zone walk
dnsrecon -z -d domain.com
```
{% endtab %}

{% tab title="DNSMap" %}
[DNSMap](https://github.com/makefu/dnsmap) scans a domain for common subdomains using a built-in or an external wordlist (if specified using -w option). The internal wordlist has around 1000 words

```bash
#Brute force domains and hosts
dnsmap domain.com -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
```
{% endtab %}

{% tab title="DNSEnum" %}
[DNSEnum](https://github.com/fwaeytens/dnsenum) Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain.

```bash
dnsenum domain.com
```
{% endtab %}

{% tab title="dnsdumpster" %}
[dnsdumpster](https://dnsdumpster.com/) is a usefull website to perform DNS enumeration.
{% endtab %}
{% endtabs %}

## Ressource

{% embed url="https://attack.mitre.org/techniques/T1590/002/" %}

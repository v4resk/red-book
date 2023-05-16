---
description: MITRE ATT&CK™  Gather Victim Network Information - DNS - T1590.002
---

# DNS Enumeration

## Theory

Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS, MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk.

## Practice

{% tabs %}
{% tab title="dig" %}
The dig (domain information groper) command is a flexible tool for interrogating DNS name servers. It performs DNS lookups and displays the answers that are returned from the queried name server(s).

```bash
#Enum records
dig MX domain.com
dig NS domain.com
dig A domain.com
dig txt domain.com
dig AAAA domain.com
[...]

#If supported by the DNS server, we can use the ANY query and dump all records
dig any domain.com

#Zone transfert
dig axfr domain.com @ns.domain.com
```
{% endtab %}

{% tab title="DNSRecon" %}
[DNSRecon](https://github.com/darkoperator/dnsrecon) is a Python script that provides the ability to perform DNS enumeration.

```bash
#Basic enum
dnsrecon -d domain.com

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

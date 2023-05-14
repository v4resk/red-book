---
description: MITRE ATT&CK™ Account Discovery - Technique T1087
---

# Email Harvesting

## Theory

We may attempt to obtain a list of email addresses and accounts from a domain or website. This is part of passive reconnaissance. It can provide us with useful information and help us gain initial access.

## Practice

{% tabs %}
{% tab title="Curl" %}
We can recurisvly curl a website and pipe it over a regex to extract emails
```bash
curl -Rkfs https://target.url | grep -hio "\b[a-z0-9.-]\+@[a-z0-9.-]\+\.[a-z]\{2,4\}\+\b"
```
{% endtab %}

{% tab title="theHarvester" %}
[theHarvester](https://github.com/laramies/theHarvester) is used to gather open source intelligence (OSINT) on a company or domain. The tool gathers names, emails, IPs, subdomains, and URLs by using multiple public resources.
```bash
#Search using bing
theHarvester -d target.url -b bing
```
{% endtab %}

{% tab title="Whois" %}
Whois is a widely used Internet record listing that identifies who owns a domain and how to get in contact with them. We may find emails and other valuable information.
```bash
whois target.url
```
{% endtab %}
{% endtabs %}

## Ressource

{% embed url="https://ine.com/blog/exploiting-pwnkit-cve-20214034" %}


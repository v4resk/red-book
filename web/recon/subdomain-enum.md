# Subdomains enumeration

## Theory

When conducting penetration tests on a website, or on a `*.domain.com` scope, finding subdomains of the target can help widen the attack surface. There are many different techniques to find subdomains that can be divided in two main categories.

## Practice

### Passive enumeration

Passive enumeration is the process of collecting information about a specific target from publicly available sources that can be accessed by anyone. Attackers don't connect directly to the target systems and stay under the radar.

{% tabs %}
{% tab title="Subfinder " %}
[Subfinder](https://github.com/projectdiscovery/subfinder) is a fast passive subdomain enumeration tool wich rely on multiple OSINT techniques like Certificate Transparency logs enumeration.

```bash
# Standard enumeration with subfinder
subfinder -d "target.domain"

# Pipe subfinder with httpx to find HTTP services
echo "target.domain" | subfinder -silent | httpx -silent
```
{% endtab %}

{% tab title="Amass" %}
OWASP's [Amass](https://github.com/OWASP/Amass) (Go) tool can gather information through DNS bruteforcing, DNS sweeping, NSED zone walking, DNS zone transfer, through web archives, through online DNS datasets and aggregators APIs, etc.\
But we can use it to only do passive enumeration

```bash
amass enum --passive -d "domain.com"
```
{% endtab %}
{% endtabs %}

### Virtual host fuzzing

A web server can host multiple websites for multiple domain names (websites). In order to choose what website to show for what domain, many use what is called "virtual hosting". Virtual hosting can be based on a name, an IP, or a port ([read more](https://en.wikipedia.org/wiki/Virtual\_hosting#Name-based)).

When having a domain name as scope, operating virtual host (a.k.a. vhost) fuzzing is recommended to possibly find alternate domain names of subdomains that point to a virtual host.

{% tabs %}
{% tab title="Gobuster" %}
[Gobuster](https://github.com/OJ/gobuster) (go) can be used to do virtual host bruteforcing

```bash
gobuster vhost --useragent "PENTEST" --wordlist "/path/to/wordlist.txt" --url $URL
```
{% endtab %}

{% tab title="ffuf" %}
&#x20;[ffuf ](https://github.com/ffuf/ffuf)(go) can also be used to do virtual host bruteforcing

```bash
ffuf -H "Host: FUZZ.$DOMAIN" -H "User-Agent: PENTEST" -c -w "/path/to/wordlist.txt" -u $URL
```
{% endtab %}
{% endtabs %}

### Google & Bing Dorks

Search engines like Google and Bing offer Dorking features that can be used to gather specific information.

{% content-ref url="../../redteam/recon/google-dorks.md" %}
[google-dorks.md](../../redteam/recon/google-dorks.md)
{% endcontent-ref %}

### DNS Enumeration

We may try to enumerate DNS informations.

{% content-ref url="../../redteam/recon/dns-enum.md" %}
[dns-enum.md](../../redteam/recon/dns-enum.md)
{% endcontent-ref %}

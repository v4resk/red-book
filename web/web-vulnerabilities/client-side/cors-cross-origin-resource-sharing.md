# CORS (Cross-origin resource sharing)

## Theory

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy ([SOP](https://portswigger.net/web-security/cors/same-origin-policy)). However, it also provides potential for cross-domain attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as [cross-site request forgery](https://portswigger.net/web-security/csrf) ([CSRF](https://portswigger.net/web-security/csrf)).

<figure><img src="../../../.gitbook/assets/attack-on-cors.svg" alt=""><figcaption><p>attack-on-cors - portswigger</p></figcaption></figure>

### Same-origin Policy

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain. The same-origin policy was defined many years ago in response to potentially malicious cross-domain interactions, such as one website stealing private data from another. It generally allows a domain to issue requests to other domains, but not to access the responses.

### Relaxation of the same-origin policy

The same-origin policy is very restrictive and consequently various approaches have been devised to circumvent the constraints. Many websites interact with subdomains or third-party sites in a way that requires full cross-origin access. A controlled relaxation of the same-origin policy is possible using **cross-origin resource sharing (CORS).**

The cross-origin resource sharing protocol uses a suite of HTTP headers that define trusted web origins and associated properties such as whether authenticated access is permitted. These are combined in a header exchange between a browser and the cross-origin web site that it is trying to access.

## Practice

Many modern websites use CORS to allow access from subdomains and trusted third parties. Their implementation of CORS may contain mistakes or be overly lenient to ensure that everything works, and this can result in exploitable vulnerabilities.

### Tools

{% tabs %}
{% tab title="One-Liner" %}
Here are some handy one-liners to automate CORS scans on domains using tools like [gau](https://github.com/lc/gau), [hakrawler](https://github.com/hakluke/hakrawler), [waybackurls](https://github.com/tomnomnom/waybackurls), [katana](https://github.com/projectdiscovery/katana).

{% hint style="success" %}
It may be usefull for bug bounty hunting
{% endhint %}

{% hint style="info" %}
**domains.txt** -> text file containing domain names (ex: test.domain.com)
{% endhint %}

```bash
# CURL One-Liner
cat domains.txt | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://portswigger.net/web-security/learning-paths/cors" %}

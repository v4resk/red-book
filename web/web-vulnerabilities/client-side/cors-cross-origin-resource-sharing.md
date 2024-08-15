# CORS (Cross-origin resource sharing)

## Theory

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy ([SOP](https://portswigger.net/web-security/cors/same-origin-policy)). However, it also provides potential for cross-domain attacks, if a website's CORS policy is poorly configured and implemented. CORS is not a protection against cross-origin attacks such as [cross-site request forgery](https://portswigger.net/web-security/csrf) ([CSRF](https://portswigger.net/web-security/csrf)).

<figure><img src="../../../.gitbook/assets/attack-on-cors.svg" alt=""><figcaption></figcaption></figure>

## Practice

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

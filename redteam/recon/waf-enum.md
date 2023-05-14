# WAF Enumeration

## Theory

WAF (Web Application Firewall) is a specific form of application firewall that filters, monitors, and blocks HTTP traffic to and from a web service. We can try to identify and fingerprint it and thus facilitate the bypass process. 

## Practice

{% tabs %}
{% tab title="wafw00f" %}
[wafw00f](https://github.com/EnableSecurity/wafw00f) allows to identify and fingerprint Web Application Firewall (WAF) products protecting a website.
```bash
#Basic scan
wafw00f https://domain.com

#Test all WAF
wafw00f https://domain.com -a
```
{% endtab %}
{% endtabs %}

## Ressource

{% embed url="https://github.com/EnableSecurity/wafw00f" %}



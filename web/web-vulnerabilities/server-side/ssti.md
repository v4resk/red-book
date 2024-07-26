# SSTI (Server-Side Template Injection)

## Theory

Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

## Practice

### Tools <a href="#detect" id="detect"></a>

{% tabs %}
{% tab title="Tplmap" %}
[Tplmap](https://github.com/epinna/tplmap) is a Server-Side Template Injection and Code Injection detection and exploitation tool.

```bash
./tplmap.py -u 'http://www.target.com/page?name=John'
```
{% endtab %}

{% tab title="One-Liner" %}
Here is an handy one-liner to automate SSTI scans on multiple URLs using tools like [gau](https://github.com/lc/gau), [hakrawler](https://github.com/hakluke/hakrawler), [waybackurls](https://github.com/tomnomnom/waybackurls), [katana](https://github.com/projectdiscovery/katana), [uro](https://github.com/s0md3v/uro), [qsreplace](https://github.com/tomnomnom/qsreplace), [httpx](https://github.com/projectdiscovery/httpx), [Gxss](https://github.com/KathanP19/Gxss), [Dalfox](https://github.com/hahwul/dalfox).

{% hint style="success" %}
It may be usefull for bug bounty hunting
{% endhint %}

```bash
# tplmap from targets url file
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
{% endtab %}
{% endtabs %}

### Fuzzing

{% tabs %}
{% tab title="Payload" %}
We have to identify input vectors that may not be properly sanitized in GET and POST parameters. For this, we may fuzz parameters using the following payload

```none
${{<%[%'"}}%\
```

{% hint style="info" %}
If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way.
{% endhint %}
{% endtab %}
{% endtabs %}

### Identify Template Engine

Once you have detected the template injection, the next step is to identify the template engine.

{% tabs %}
{% tab title="Payloads" %}
By manually testing different language-specific payloads and study how they are interpreted by the target, we may identify the template engine.

| Payload             | Template Engine/Framework/Language                     |
| ------------------- | ------------------------------------------------------ |
| `a{*comment*}b`     | Smarty                                                 |
| `#{ 2*3 }`          | Pug, Spring                                            |
| `*{ 2*3 }`          | Spring                                                 |
| `${"z".join("ab")}` | Mako, ???                                              |
| `{{ '7'*7 }}`       | Angular, Django, Flask, Go, Jinja2, Tornado, Twig, ??? |
| `{{:2*3}}`          | JsRender                                               |
| `{% debug %}`       | Django                                                 |
{% endtab %}

{% tab title="Errors" %}
Simply submitting invalid syntax is often enough because the resulting error message will tell you exactly what the template engine is, and sometimes even which version.

Some possible payloads that may cause errors:

| `${}`       | `{{}}`       | `<%= %>`        |
| ----------- | ------------ | --------------- |
| `${7/0}`    | `{{7/0}}`    | `<%= 7/0 %>`    |
| `${foobar}` | `{{foobar}}` | `<%= foobar %>` |
| `${7*7}`    | `{{7*7}}`    | \`\`            |
{% endtab %}

{% tab title="Decisional Tree" %}
The following tree can be used to identify which template engine is used

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>SSTI decision tree</p></figcaption></figure>
{% endtab %}
{% endtabs %}

## Exploit

Once you have identified the engine, refers to the corresponding page to exploit it:

* [Angular](https://exploit-notes.hdks.org/exploit/web/framework/javascript/angular-pentesting/)
* [Django](https://exploit-notes.hdks.org/exploit/web/framework/python/django-pentesting/)
* [Flask/Jinja2](https://exploit-notes.hdks.org/exploit/web/framework/python/flask-jinja2-pentesting/)
* [Go](https://exploit-notes.hdks.org/exploit/web/go-ssti/)
* [JsRender](https://exploit-notes.hdks.org/exploit/web/template-engine/jsrender-template-injection/)
* [Pug](https://exploit-notes.hdks.org/exploit/web/template-engine/pug-pentesting/)
* [Spring](https://exploit-notes.hdks.org/exploit/web/framework/java/spring-pentesting/)
* [Tornado](https://exploit-notes.hdks.org/exploit/web/framework/python/tornado-pentesting/)

## Resources&#x20;

{% embed url="https://exploit-notes.hdks.org/exploit/web/security-risk/ssti/" %}

{% embed url="https://portswigger.net/web-security/server-side-template-injection" %}

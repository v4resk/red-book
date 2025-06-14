# Cred Network protocols

## Theory

Plaintext protocols (like HTTP, FTP, SNMP, SMTP) are widely used within organizations. Being able to capture and parse that traffic could offer attackers valuable information like sensitive files, passwords or hashes. There are many ways an attacker can obtain a [man-in-the-middle](../../../ad/movement/mitm-and-coerced-authentications/) position, [ARP poisoning](../../../ad/movement/mitm-and-coerced-authentications/arp-poisoning.md) being the most common and effective one.

## Practice

Once network traffic is hijacked and goes through an attacker-controlled equipement, valuable information can searched through captured (with [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html), [tshark ](https://www.wireshark.org/docs/man-pages/tshark.html)or [wireshark](https://www.wireshark.org/)) or through live traffic.

{% tabs %}
{% tab title="PCredz" %}
[PCredz ](https://github.com/lgandx/PCredz)(Python) is a good example and allows extraction of credit card numbers, NTLM (DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23, i.e. [ASREQroast](../../../ad/movement/kerberos/asreqroast.md)), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

```bash
# extract credentials from a pcap file
Pcredz -f "file-to-parse.pcap"

# extract credentials from all pcap files in a folder
Pcredz -d "/path/to/pcaps/"

# extract credentials from a live packet capture on a network interface
Pcredz -i $INTERFACE -v
```
{% endtab %}

{% tab title="tcpdump" %}
You can use `tcpdump` to capture raw packets and analyze them.

```bash
#Capture all traffic to a .pcap file:
tcpdump -i eth0 -w /tmp/capture.pcap
```

```bash
#Or target specific traffic types (e.g., SMB, LDAP, FTP):
tcpdump -i eth0 port 445 or port 389 or port 21 -w /tmp/capture.pcap
```

{% hint style="info" %}
You can make it run for a while, then Ctrl+C to stop.\
&#x20;The `.pcap` file can then be parsed offline using Pcredz or Wireshark.
{% endhint %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://github.com/lgandx/PCredz" %}

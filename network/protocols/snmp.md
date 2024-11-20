---
description: Pentesting SNMP - UDP Ports 161,162,10161,10162
---

# SNMP

## Theory

SNMP - Simple Network Management Protocol is a protocol used to monitor different devices in the network (like routers, switches, printers, IoTs...).

SNMP is based on UDP, a simple, stateless protocol, and is therefore susceptible to IP spoofing and replay attacks. Additionally, the commonly used SNMP protocols 1, 2, and 2c offer no traffic encryption, meaning that SNMP information and credentials can be easily intercepted over a local network. Traditional SNMP protocols also have weak authentication schemes and are commonly left configured with default public and private community strings.

SNMP protocol operate on different ports depending on the type of communication:

* The SNMP agent receives requests on UDP port **161**.
* The manager receives notifications ([Traps](https://en.wikipedia.org/wiki/Simple\_Network\_Management\_Protocol#Trap) & [InformRequests](https://en.wikipedia.org/wiki/Simple\_Network\_Management\_Protocol#InformRequest)) on port **162**.
* When used with TLS or DTLS, requests are received on port **10161** and notifications are sent to port **10162**.

### MIB

To ensure that SNMP access works across manufacturers and with different client-server combinations, the Management Information Base (MIB) was created. MIB is an independent format for storing device information. A MIB is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy.&#x20;

### OIDs

OIDs stands for Object Identifiers. OIDs uniquely identify managed objects in a MIB hierarchy. This can be depicted as a tree, the levels of which are assigned by different organizations. Top level MIB object IDs (OIDs) belong to different standard organizations.\
**Vendors define private branches including managed objects for their own products.**

You can navigate through an OID tree from here: [http://www.oid-info.com/cgi-bin/display?tree=#focus](http://www.oid-info.com/cgi-bin/display?tree=#focus)

You can see what a OID means accessing (ex `1.3.6.1.2.1.1`): [http://oid-info.com/get/1.3.6.1.2.1.1](http://oid-info.com/get/1.3.6.1.2.1.1)

### SNMP Versions

There are 2 important versions of SNMP:

* **SNMPv1**: Main one, it is still the most frequent, the **authentication is based on a string** (community string) that travels in **plain-text** (all the information travels in plain text). **Version 2 and 2c** send the **traffic in plain text** also and uses a **community string as authentication**.
* **SNMPv3**: Uses a better **authentication** form and the information travels **encrypted** using (**dictionary attack** could be performed but would be much harder to find the correct creds than in SNMPv1 and v2).

### Community Strings

As mentioned before, in order to access the information saved on the MIB you need to know the community string on versions 1 and 2/2c and the credentials on version 3.\
The are 2 types of community strings:

* **`public`** mainly **read only** functions
* **`private`** **Read/Write** in general

Note that the writability of an OID **depends on the community string used**, so even if you find that "public" is being used, you could be able to write some values. Also, there may exist objects which are always "Read Only".\
If you try to **write** an object a **`noSuchName` or `readOnly` error** is received.

In versions 1 and 2/2c if you to use a **bad** community string the server wont **respond**. So, if it responds, a **valid community strings was used**.

## Practice

### Bruteforce Community Strings (v1 and v2c)&#x20;

{% tabs %}
{% tab title="Onesixtyone" %}
Alternatively, we can use a tool such as [onesixtyone](https://github.com/trailofbits/onesixtyone), which will attempt a brute force attack against an IP or list of IP addresses.

```bash
# Single host
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <TARGET_IP>

# Scan a subnet with public string
onesixtyone 192.168.4.0/24 public

# Targets file
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -i <TARGETS_FILE>
```
{% endtab %}

{% tab title="Hydra" %}
We may bruteforce community strings using hydra

```sh
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target-ip> snmp
```
{% endtab %}
{% endtabs %}

### Enumerate

{% tabs %}
{% tab title="Snmpwalk" %}
We can probe and query SNMP values using the snmpwalk tool

```bash
# -v: SNMP version
# -c: Community string
# -t: Timeout (in seconds)
# -Oa: translate any hexadecimal string into ASCII
# Enum all
snmpwalk -v <SNMP_VERSION> -c <COMMUNITY_STRING> -t 10 <TARGET_IP> .1

# ASCII mode
snmpwalk -v <SNMP_VERSION> -c <COMMUNITY_STRING> -t 10 -Oa <TARGET_IP> .1

# Get extended
snmpwalk -v <SNMP_VERSION> -c <COMMUNITY_STRING> -t 10 <TARGET_IP> NET-SNMP-EXTEND-MIB::nsExtendObject
snmpwalk -v <SNMP_VERSION> -c <COMMUNITY_STRING> -t 10 <TARGET_IP>NET-SNMP-EXTEND-MIB::nsExtendOutputFull

# Get IPv6 (needed dec2hex)
snmpwalk -v <SNMP_VERSION> -c <COMMUNITY_STRING> -t 10 <TARGET_IP> 1.3.6.1.2.1.4.34.1.3

# Enumerate Users (Microsoft Windows SNMP)
snmpwalk -v <SNMP_VERSION> -c <COMMUNITY_STRING> -t 10 <TARGET_IP> 1.3.6.1.4.1.77.1.2.25
```

These MIB values correspond to specific Microsoft Windows SNMP parameters that may be interesting to us.

| MIB Value              | Parameter        |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |
{% endtab %}

{% tab title="Nmap" %}
Following nmap scripts can help us enumerating SNMP

```bash
nmap -sU --script snmp-info -p 161 <TARGET_IP>
nmap -sU --script snmp-interfaces -p 161 <TARGET_IP>
nmap -sU --script snmp-processes -p 161 <TARGET_IP>
nmap -sU --script snmp-sysdescr -p 161 <TARGET_IP>
nmap -sU --script snmp* -p 161 <TARGET_IP>
```
{% endtab %}

{% tab title="Snmp-Check" %}
[Snmp-Check](https://www.kali.org/tools/snmpcheck/) is an SNMP enumerator.

```bash
# -c: Community string
# -p: Target port
snmp-check <TARGET_IP> -p 161 -c <COMMUNITY_STRING>

# Example
snmp-check 10.10.10.8 -p 161 -c public
```
{% endtab %}
{% endtabs %}

## Find Juicy Information

{% hint style="info" %}
FoThe following commands allow you to quickly find juicy information in a file containing all SNMP data.

```bash
# For example, the file could be created as follows
snmpwalk -v 1 -c public 10.10.10.8 .1 > dump.snmp
```
{% endhint %}

{% tabs %}
{% tab title="Identify private string" %}
As an example, if we can identify the private community string used by an organization on their Cisco IOS routers, then we could possibly use that community string to extract the running configurations from those routers.&#x20;

The best method for finding such data has often been related to SNMP Trap data. So again, using the following grep we can parse through a lot of MIB data quickly searching for the key word of “trap”:

```bash
grep -i "trap" *.snmp
```
{% endtab %}

{% tab title="Devices" %}
The sysDesc .1.3.6.1.2.1.1.1.0 MIB data allow us to determine what devices we have harvested information from. This can easily be done using the following grep command:

```bash
grep ".1.3.6.1.2.1.1.1.0" *.snmp
```
{% endtab %}

{% tab title="Usernames/passwords" %}
Another area of interest is logs, there are some devices that hold logs within the MIB tables. These logs can also contain failed logon attempts. By chance, a user may inadvertently entered a password as the username via Telnet or SSH.

```bash
grep -i "login\|fail" *.snmp
```
{% endtab %}

{% tab title="Emails" %}
We may find emails in MIB tables

```bash
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" *.snmp
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp" %}

{% embed url="https://exploit-notes.hdks.org/exploit/network/protocol/snmp-pentesting/" %}

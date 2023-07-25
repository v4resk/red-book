---
description: Port 1521,1522-1529
---

# 🛠️ Oracle TNS

## Theory

Oracle clients communicate with the database using the Transparent Network Substrate (TNS) protocol. When the listener receives a connection request (1521/TCP, -you may also get secondary listeners on 1522–1529-), it starts up a new database process and establishes a connection between the client and the Oracle database.

## Practice&#x20;

#### &#x20;**Enumerate v**ersion

{% tabs %}
{% tab title="nmap" %}
Using nmap scripts, we can enumerate the version of the TNS-Listener

```bash
nmap --script "oracle-tns-version" -p 1521 -T4 -sV <IP>
```
{% endtab %}

{% tab title="tnscmd10g" %}
We can enumerate the TNS-Listener using the [tnscmd10g](https://www.kali.org/tools/tnscmd10g/) tool

```bash
tnscmd10g version -p 1521 -h <IP>
```
{% endtab %}
{% endtabs %}

#### **Commands & Brute-force**

{% tabs %}
{% tab title="tnscmd10g" %}
When enumerating Oracle the first step is to talk to the TNS-Listener

```bash
# Return the current status and variables used by the listener
tnscmd10g status -p 1521 -h <IP>

# Dump service data
tnscmd10g services -p 1521 -h <IP>

# Dump debugging information to the listener log
tnscmd10g debug -p 1521 -h <IP>

# Write the listener configuration file to a backup location
tnscmd10g save_config -p 1521 -h <IP>
```

{% hint style="danger" %}
If you **receive an error**, could be because **TNS versions are incompatible** (Use the `--10G` parameter with `tnscmd10`) and if the **error persist,** the listener may be **password protected**&#x20;
{% endhint %}

We can use hydra to brute-force TNS-Listener password

```bash
hydra -P rockyou.txt -t 32 -s 1521 <IP> oracle-listener
```
{% endtab %}
{% endtabs %}

#### SID enumeration

{% tabs %}
{% tab title="Enumerate" %}
The SID (Service Identifier) is essentially the database name, depending on the install you may have one or more default SIDs, or even a totally custom dba defined SID.

{% hint style="info" %}
In some old versions (in **9** it works) you could ask for the SID using **`tnscmd10g status`**`,` SIDs will be inside: SERVICE=(SERVICE\_NAME=\<SID\_NAME>)
{% endhint %}

We can brute-force SID as follow using [Hydra](https://github.com/vanhauser-thc/thc-hydra) or [Odat](https://github.com/quentinhardy/odat)

```bash
#Using Hydra
hydra -L sid.txt -s 1521 <IP> oracle-sid

#Using odat
./odat.py sidguesser -s $SERVER -d $SID --sids-file=./sids.txt

# Interesting Wordilists
cat /usr/share/metasploit-framework/data/wordlists/sid.txt
cat /usr/share/nmap/nselib/data/oracle-sids
```
{% endtab %}
{% endtabs %}

## Resources

[https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)

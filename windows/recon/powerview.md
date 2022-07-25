# PowerView

## Theory

[PowerView](https://github.com/PowerShellMafia/PowerSploit) is a recon script part of the PowerSploit project

## Practice

### Users, Groups & Computers Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
# Users
Get-NetUser #Get users with several (not all) properties
Get-NetUser | select -ExpandProperty samaccountname #List all usernames
Get-NetUser -UserName student107 #Get info about a user
Get-NetUser -properties name, description #Get all descriptions
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount  #Get all pwdlastset, logoncount and badpwdcount
Find-UserField -SearchField Description -SearchTerm "built" #Search account with "something" in a parameter

# Users Filters
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -properties distinguishedname #All enabled users
Get-NetUser -UACFilter ACCOUNTDISABLE #All disabled users
Get-NetUser -UACFilter SMARTCARD_REQUIRED #Users that require a smart card
Get-NetUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname #Not smart card users
Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
Get-NetUser -PreauthNotRequired #ASREPRoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Get-Netuser -TrustedToAuth #Useful for Kerberos constrain delegation
Get-NetUser -AllowDelegation -AdminCount #All privileged users that aren't marked as sensitive/not for delegation
# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-ObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}

#Groups
Get-NetGroup #Get groups
Get-NetGroup -Domain mydomain.local #Get groups of an specific domain
Get-NetGroup 'Domain Admins' #Get all data of a group
Get-NetGroup -AdminCount #Search admin grups
Get-NetGroup -UserName "myusername" #Get groups of a user
Get-NetGroupMember -Identity "Administrators" -Recurse #Get users inside "Administrators" group. If there are groups inside of this grup, the -Recurse option will print the users inside the others groups also
Get-NetGroupMember -Identity "Enterprise Admins" -Domain mydomain.local #Remember that "Enterprise Admins" group only exists in the rootdomain of the forest
Get-NetLocalGroup -ComputerName dc.mydomain.local -ListGroups #Get Local groups of a machine (you need admin rights in no DC hosts)
Get-NetLocalGroupMember -computername dcorp-dc.dollarcorp.moneycorp.local #Get users of localgroups in computer
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs #Check AdminSDHolder users
Get-NetGPOGroup #Get restricted groups

# Computers
Get-NetComputer #Get all computer objects
Get-NetComputer -Ping #Send a ping to check if the computers are working
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
Get-NetComputer -TrustedToAuth #Find computers with Constrined Delegation
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} #Find any machine accounts in privileged groups
```

{% endtab %}
{% endtabs %}

### Domain Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
# Domain Info
Get-NetDomain #Get info about the current domain
Get-NetDomain -Domain mydomain.local
Get-DomainSID #Get domain SID

# Policy
Get-DomainPolicy #Get info about the policy
(Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."SystemAccess" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges

# Domain Controller
Get-NetDomainController -Domain mydomain.local #Get Domain Controller
```

{% endtab %}
{% endtabs %}

### Misc Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
Get-NetDomain #Basic domain info
#User info
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount #Basic user enabled info
Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
Get-NetUser -PreauthNotRequired #ASREPRoastable users
Get-NetUser -SPN #Kerberoastable users
#Groups info
Get-NetGroup | select samaccountname, admincount, description
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=EGOTISTICAL-BANK,DC=local' | %{ $_.SecurityIdentifier } | Convert-SidToName #Get AdminSDHolders
#Computers
Get-NetComputer | select samaccountname, operatingsystem
Get-NetComputer -Unconstrained | select samaccountname #DCs always appear but aren't useful for privesc
Get-NetComputer -TrustedToAuth | select samaccountname #Find computers with Constrained Delegation
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} #Find any machine accounts in privileged groups
#Shares
Find-DomainShare -CheckShareAccess #Search readable shares
#Domain trusts
Get-NetDomainTrust #Get all domain trusts (parent, children and external)
Get-NetForestDomain | Get-NetDomainTrust #Enumerate all the trusts of all the domains found
#LHF
#Check if any user passwords are set
$FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl
#Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
Find-LocalAdminAccess
#Get members from Domain Admins (default) and a list of computers and check if any of the users is logged in any machine running Get-NetSession/Get-NetLoggedon on each host. If -Checkaccess, then it also check for LocalAdmin access in the hosts.
Invoke-UserHunter -CheckAccess
#Find interesting ACLs
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl
```

{% endtab %}
{% endtabs %}

### Logon Users/ Session Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
Get-NetLoggedon -ComputerName <servername> #Get net logon users at the moment in a computer (need admins rights on target)
Get-NetSession -ComputerName <servername> #Get active sessions on the host
Get-LoggedOnLocal -ComputerName <servername> #Get locally logon users at the moment (need remote registry (default in server OS))
Get-LastLoggedon -ComputerName <servername> #Get last user logged on (needs admin rigths in host)
Get-NetRDPSession -ComputerName <servername> #List RDP sessions inside a host (needs admin rights in host)
```

{% endtab %}
{% endtabs %}

### Shares Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
Get-NetFileServer #Search file servers. Lot of users use to be logged in this kind of servers
Find-DomainShare -CheckShareAccess #Search readable shares
Find-InterestingDomainShareFile #Find interesting files, can use filters
```

{% endtab %}
{% endtabs %}

### GPO & OU Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
#GPO
Get-NetGPO #Get all policies with details
Get-NetGPO | select displayname #Get the names of the policies
Get-NetGPO -ComputerName <servername> #Get the policy applied in a computer
gpresult /V #Get current policy
# Enumerate permissions for GPOs where users with RIDs of > -1000 have some kind of modification/control rights
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}
Get-NetGPO -GPOName '{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}' #Get GPO of an OU

#OU
Get-NetOU #Get Organization Units
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_} #Get all computers inside an OU (StudentMachines in this case)
```

{% endtab %}
{% endtabs %}

### ACL Enumeration

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.


```bash
Get-ObjectAcl -SamAccountName <username> -ResolveGUIDs #Get ACLs of an object (permissions of other objects over the indicated one)
Get-PathAcl -Path "\\dc.mydomain.local\sysvol" #Get permissions of a file
Find-InterestingDomainAcl -ResolveGUIDs #Find intresting ACEs (Interesting permisions of "unexpected objects" (RID>1000 and modify permissions) over other objects
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"} #Check if any of the interesting permissions founds is realated to a username/group
Get-NetGroupMember -GroupName "Administrators" -Recurse | ?{$_.IsGroup -match "false"} | %{Get-ObjectACL -SamAccountName $_.MemberName -ResolveGUIDs} | select ObjectDN, IdentityReference, ActiveDirectoryRights #Get special rights over All administrators in domain
```

{% endtab %}
{% endtabs %}


### Others & Tricks

{% tabs %}
{% tab title="Windows" %}
PowerView ([sources])(https://github.com/PowerShellMafia/PowerSploit), can be imported as a powershell module in order to perform enumeration on the box.

We can convert a SID to a Name
```bash
"S-1-5-21-1874506631-3219952063-538504511-2136" | Convert-SidToName
```

RunAs users
```bash
# use an alterate creadential for any function
$SecPassword = ConvertTo-SecureString 'BurgerBurgerBurger!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUser -Credential $Cred
```

Impersonate an user
```bash
# if running in -sta mode, impersonate another credential a la "runas /netonly"
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred
# ... action
Invoke-RevertToSelf
```

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview" %}


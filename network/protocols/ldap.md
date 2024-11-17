---
description: Ports TCP 389,3268,636,3269
---

# LDAP

## Theory

LDAP (Lightweight Directory Access Protocol) is a software protocol for enabling anyone to **locate** organizations, individuals, and other **resources** such as files and devices in a network, whether on the public Internet or on a corporate intranet. LDAP is a "lightweight" (smaller amount of code) version of Directory Access Protocol (DAP).

An LDAP directory is organized in a simple "tree" hierarchy consisting of the following levels:

* The root directory (the starting place or the source of the tree), which branches out to
* Countries, each of which branches out to
* Organizations, which branch out to
* Organizational units (divisions, departments, and so forth), which branches out to (includes an entry for)
* Individuals (which includes people, files, and shared resources such as printers)

It run on port TCP 389 and 636(ldaps). The Global Catalog (LDAP in ActiveDirectory) is available by default on ports 3268, and 3269 for LDAPS.

## Practice

A lot of information on an AD domain can be obtained through LDAP. Most of the information can only be obtained with an authenticated bind but metadata (naming contexts, DNS server name, Domain Functional Level (DFL)) can be obtainable anonymously, even with anonymous binding disabled.

#### UNIX-Like

{% tabs %}
{% tab title="ldapsearch" %}
The [ldapsearch](https://linux.die.net/man/1/ldapsearch) command is a shell-accessible interface to the [ldap\_search\_ext(3)](https://linux.die.net/man/3/ldap\_search\_ext) library call. It can be used to enumerate essential informations.

**Anonymous Enumeration:**

Enumerate the base domain.

```bash
#Simple bind authentification (-x) as anonymous.
ldapsearch -H ldap://$IP -x -s base namingcontexts
```

Dump all readable ldap information as anonymous.

```bash
ldapsearch -H ldap://$IP -x -b "DC=contoso,DC=local"
```

Dump ldap information as anonymous and filter.

```bash
#With (objectClass=User) as the query and sAMAccountName the filter.
ldapsearch -H ldap://$IP -x -b "DC=contoso,DC=local" '(objectClass=User)' sAMAccountName
```

**Authenticated Enumeration:**

Dump readable ldap informations with **NTLM** based authentication

```bash
#With (objectClass=User) as the query and sAMAccountName the filter.
ldapsearch -H ldap://$IP -x -D "CN=MyUser,CN=Users,DC=contoso,DC=local" -w Password1 -b "DC=contoso,DC=local" '(objectClass=User)' sAMAccountName
ldapsearch -H ldap://$IP -x -D "MyUser@contoso.local" -w Password1 -b "DC=contoso,DC=local" '(objectClass=User)' sAMAccountName
```

Dump all readable ldap informations with **Kerberos** based authentication

```bash
#Get TGT
kinit MyUser@contoso.local

#List tickets
klist

#LdapSearch
ldapsearch -H ldap://$IP -Y GSSAPI -b "DC=contoso,DC=local" '(objectClass=User)' sAMAccountName
```

{% hint style="info" %}
If you have the following error using ldaps: **ldap\_sasl\_bind(SIMPLE): Can't contact LDAP server (-1),** it's probably because of an invalide certificate.

You can run following command to ignore the certificate:

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://<IP> [....] 
```
{% endhint %}

{% hint style="info" %}
We may use ldapsearch output (also known as LDIF files) and covert it into JSON files ingestible by BloodHound using [ldif2bloodhound](https://github.com/SySS-Research/ldif2bloodhound). See [this page](../../ad/recon/tools/bloodhound.md#unix-like) for more informations.
{% endhint %}
{% endtab %}

{% tab title="Powerview.py" %}
[Powerview.py](https://github.com/aniqfakhrul/powerview.py) is an alternative for the original [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script that allow us to perform Powerview commands directly from our attacking host using LDAP.

First we need to authenticate using similar commands

```bash
### Authenticate
# Simple
powerview $DOMAIN/$USER:$PASSWORD@$TARGET_IP --dc-ip $DC_IP
# Pass the ticket
powerview $DOMAIN/$USER@$TARGET_IP --dc-ip $DC_IP -k --no-pass
# Pass the key
powerview $DOMAIN/$USER@$TARGET_IP --dc-ip $DC_IP --aes-key $AES_KEY
# Pass the hash
powerview $DOMAIN/$USER@$TARGET_IP --dc-ip $DC_IP -H $NTLM_HASH

### Protocols
# Use LDAP (Port 389)
powerview $DOMAIN/$USER:$PASSWORD@$TARGET_IP --dc-ip $DC_IP --ldap
# Use LDAPS (Port 636)
powerview $DOMAIN/$USER:$PASSWORD@$TARGET_IP --dc-ip $DC_IP --ldap
# Use LDAP Global Catalog (Port 3268)
powerview $DOMAIN/$USER:$PASSWORD@$TARGET_IP --dc-ip $DC_IP --ldap
# Use LDAPS Global Catalog  (Port 3269)
powerview $DOMAIN/$USER:$PASSWORD@$TARGET_IP --dc-ip $DC_IP --ldap
```

Once connected, we should be able to use the powerview.py console. Here are a few examples.

```bash
(LDAP)-[10.10.16.2]-[CONTOSO\SimpleUser]
PV > Get-DomainUser -SPN -Select samaccountname,msDS-SupportedEncryptionTypes

DAP)-[10.10.16.2]-[CONTOSO\SimpleUser]
PV > Get-DomainUser -PreAuthNotRequired
```
{% endtab %}

{% tab title="NetExec" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) also has useful modules that can be used to

* map information regarding [AD-CS (Active Directory Certificate Services)](../../ad/movement/ad-cs/)
* show subnets listed in AD-SS (Active Directory Sites and Services)
* list the users description
* print the [Machine Account Quota](../../ad/movement/domain-settings/machineaccountquota.md) domain-level attribute's value

```bash
# list PKIs/CAs
netexec ldap "domain_controller" -d "domain" -u "user" -p "password" -M adcs

# list subnets referenced in AD-SS
netexec ldap "domain_controller" -d "domain" -u "user" -p "password" -M subnets

# machine account quota
netexec ldap "domain_controller" -d "domain" -u "user" -p "password" -M maq

# users description
netexec ldap "domain_controller" -d "domain" -u "user" -p "password" -M get-desc-users
```

The PowerShell equivalent to NetExec's `subnets` modules is the following

```powershell
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites.Subnets
```
{% endtab %}

{% tab title="ldapsearch-ad" %}
The [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) Python script can also be used to enumerate essential information like domain admins that have their password set to never expire, default password policies and the ones found in GPOs, trusts, kerberoastable accounts, and so on.

```bash
ldapsearch-ad --type all --server $DOMAIN_CONTROLLER --domain $DOMAIN --username $USER --password $PASSWORD
```

The FFL (Forest Functional Level), DFL (Domain Functional Level), DCFL (Domain Controller Functionality Level) and naming contexts can be listed with the following command.

```bash
ldapsearch-ad --type info --server $DOMAIN_CONTROLLER --domain $DOMAIN --username $USER --password $PASSWORD
```
{% endtab %}

{% tab title="windapsearch" %}
The windapsearch script ([Go](https://github.com/ropnop/go-windapsearch) (preferred) or [Python](https://github.com/ropnop/windapsearch)) can be used to enumerate basic but useful information.

```bash
# enumerate users (authenticated bind)
windapsearch -d $DOMAIN -u $USER -p $PASSWORD --dc $DomainController --module users

# enumerate users (anonymous bind)
windapsearch --dc $DomainController --module users

# obtain metadata (anonymous bind)
windapsearch --dc $DomainController --module metadata
```
{% endtab %}

{% tab title="ldapdomaindump" %}
[ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) is an Active Directory information dumper via LDAP, outputting information in human-readable HTML files.

```bash
ldapdomaindump --user 'DOMAIN\USER' --password $PASSWORD --outdir ldapdomaindump $DOMAIN_CONTROLLER
```
{% endtab %}

{% tab title="ntlmrelayx" %}
With [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python), it is possible to gather lots of information regarding the domain users and groups, the computers, [ADCS](../../ad/movement/ad-cs/), etc. through a [NTLM authentication relayed](../../ad/movement/ntlm/relay.md) within an LDAP session.

```bash
ntlmrelayx -t "ldap://domaincontroller" --dump-adcs --dump-laps --dump-gmsa
```
{% endtab %}
{% endtabs %}

#### Windows

{% tabs %}
{% tab title="PowerShell" %}
Using PowerShell and .NET classes, we can enumerate the domain using LDAP. This can be very handy if we have compromised a computer in the domain with no administrative access and no RSAT module installed.

To acheive this, we can use the following function.

{% code title="ldapsearch.ps1" %}
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName

    $DIR_ENTRY = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DN")

    $DIR_SEARCHER = New-Object System.DirectoryServices.DirectorySearcher($DIR_ENTRY, $LDAPQuery)

    return $DIR_SEARCHER.FindAll()

}
```
{% endcode %}

```powershell
# Import the function
. .\ldapsearch.ps1
```

Then, we can use it as in following examples, by specifing our filter.

```powershell
# Dump all objects
LDAPSearch -LDAPQuery '(objectClass=*)'

# Enum Users
## Filter on Users
LDAPSearch -LDAPQuery "(objectClass=User)"

## Print some properties for each users
$res = foreach ($obj in $(LDAPSearch -LDAPQuery "objectClass=User")) {$obj.properties | select {$_.name}, {$_.memberof}}
$res|fl

# Enum Groups
## Filter on Groups
LDAPSearch -LDAPQuery "(objectClass=Group)"

## Print some properties for each groups
$res = foreach ($obj in $(LDAPSearch -LDAPQuery "objectClass=Group")) {$obj.properties | select {$_.cn}, {$_.member}}
$res|fl

## Query for specific group and print a property
$res = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Domain Admins))"
$res.properties.member
```
{% endtab %}

{% tab title="PowerView" %}
Some [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) functions use LDAP to retreive information.

```powershell
# Import it
Import-Module .\PowerView.ps1

# Enum Domain CN
Get-NetDomain

# Enum Groups
Get-NetGroup
Get-NetGroup "Domain Admins"
Get-NetGroup | select cn

# Enum Users
Get-NetUser
Get-NetUser "user01"
Get-NetUser | select cn,pwdlastset,lastlogon
```

Fore more powerview commands and enumeration, refer to [this page](../../ad/recon/tools/powerview.md).
{% endtab %}
{% endtabs %}

{% hint style="info" %}
LDAP anonymous binding is usually disabled but it's worth checking. It could be handy to list the users and test for [ASREProasting](../../ad/movement/kerberos/asreproast.md) (since this attack needs no authentication).
{% endhint %}

{% hint style="success" %}
**Automation and scripting**

* A more advanced LDAP enumeration can be carried out with BloodHound (see [this](../../ad/recon/tools/bloodhound.md)).
* The enum4linux tool can also be used, among other things, for LDAP recon (see [this](../../ad/recon/tools/enum4linux.md)).
{% endhint %}

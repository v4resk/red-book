# LDAP

A lot of information on an AD domain can be obtained through LDAP. Most of the information can only be obtained with an authenticated bind but metadata (naming contexts, DNS server name, Domain Functional Level (DFL)) can be obtainable anonymously, even with anonymous binding disabled.

{% tabs %}
{% tab title="ldapsearch" %}
The [ldapsearch](https://linux.die.net/man/1/ldapsearch) command is a shell-accessible interface to the [ldap\_search\_ext(3)](https://linux.die.net/man/3/ldap\_search\_ext) library call. It can be used to enumerate essential informations.

#### Anonymous Enumeration:

Enumerate the base domain

```bash
#Simple bind authentification (-x) as anonymous.
ldapsearch -H ldap://$IP -x -s base namingcontexts
```

Dump all readable ldap informations as anonymous

```bash
ldapsearch -H ldap://$IP -x -b "DC=contoso,DC=local"
```

Dump ldap informations as anonymous and filter

```bash
#With (objectClass=User) as the query and sAMAccountName the filter.
ldapsearch -H ldap://$IP -x -b "DC=contoso,DC=local" '(objectClass=User)' sAMAccountName
```

#### Authenticated Enumeration:

Dump readable ldap informations with **NTLM** based authentication&#x20;

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
With [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python), it is possible to gather lots of information regarding the domain users and groups, the computers, [ADCS](../movement/ad-cs/), etc. through a [NTLM authentication relayed](../movement/ntlm/relay.md) within an LDAP session.

```bash
ntlmrelayx -t "ldap://domaincontroller" --dump-adcs --dump-laps --dump-gmsa
```
{% endtab %}
{% endtabs %}

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Python) also has useful modules that can be used to

* map information regarding [AD-CS (Active Directory Certificate Services)](../movement/ad-cs/)
* show subnets listed in AD-SS (Active Directory Sites and Services)
* list the users description
* print the [Machine Account Quota](../movement/domain-settings/machineaccountquota.md) domain-level attribute's value

```bash
# list PKIs/CAs
cme ldap "domain_controller" -d "domain" -u "user" -p "password" -M adcs

# list subnets referenced in AD-SS
cme ldap "domain_controller" -d "domain" -u "user" -p "password" -M subnets

# machine account quota
cme ldap "domain_controller" -d "domain" -u "user" -p "password" -M maq

# users description
cme ldap "domain_controller" -d "domain" -u "user" -p "password" -M get-desc-users
```

The PowerShell equivalent to CrackMapExec's `subnets` modules is the following

```powershell
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites.Subnets
```

{% hint style="info" %}
LDAP anonymous binding is usually disabled but it's worth checking. It could be handy to list the users and test for [ASREProasting](../movement/kerberos/asreproast.md) (since this attack needs no authentication).
{% endhint %}

{% hint style="success" %}
**Automation and scripting**

* A more advanced LDAP enumeration can be carried out with BloodHound (see [this](bloodhound.md)).
* The enum4linux tool can also be used, among other things, for LDAP recon (see [this](enum4linux.md)).
{% endhint %}

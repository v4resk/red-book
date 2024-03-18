# 🛠️ Trusts

**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name

## Theory



## Practice

### Enumeration

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, tools like [NetExec ](https://github.com/Pennyw0rth/NetExec)(Python) and [ldapsearch](https://git.openldap.org/openldap/openldap) (C) can be used to enumerate trusts.

```bash
# ldapsearch
ldapsearch -h ldap://$DC_IP -b "CN=SYSTEM,DC=$DOMAIN" "(objectclass=trustedDomain)"

# NetExec
nxc ldap <DC_IP> -u <USER>-p <PASSWORD> -M enum_trusts
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems tools like [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) and [netdom](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc772217\(v=ws.11\)) may be used to enumerate trusts :

**netdom**

From domain-joined hosts, the `netdom` cmdlet can be used.

```powershell
netdom trust /domain:DOMAIN.LOCAL
```

**PowerView**

Alternatively, [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) supports multiple commands for various purposes.

```powershell
# Enumerate domain trust relationships of the current user's domain
Get-NetDomainTrust
Get-NetDomainTrust –Domain [Domain Name]
Get-NetDomainTrust -SearchBase "GC://$($ENV:USERDNSDOMAIN)"

# Enumerate forest trusts from the current domain's perspective
Get-NetForestTrust
Get-NetForestDomain -Forest [Forest Name]

# Enumerate all the trusts of all the domains found
Get-NetForestDomain | Get-NetDomainTrust

# Enumerate and map all domain trusts
Invoke-MapDomainTrust

#Get users with privileges in other domains inside the forest
Get-DomainForeingUser

#Get groups with privileges in other domains inside the forest
Get-DomainForeignGroupMember
```

> The [global catalog is a partial copy of all objects](https://technet.microsoft.com/en-us/library/cc728188\(v=ws.10\).aspx) in an Active Directory forest, meaning that some object properties (but not all) are contained within it. This data is replicated among all domain controllers marked as global catalogs for the forest. Trusted domain objects are replicated in the global catalog, so we can enumerate every single internal and external trust that all domains in our current forest have extremely quickly, and only with traffic to our current PDC.
>
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)_)_

**BloodHound**

[BloodHound](https://www.thehacker.recipes/a-d/recon/bloodhound) can also be used to map the trusts. While it doesn't provide much details, it shows a visual representation.
{% endtab %}
{% endtabs %}

### Forging Tickets

{% tabs %}
{% tab title="UNIX-like" %}

{% endtab %}

{% tab title="Windows" %}

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN" %}

{% embed url="https://www.thehacker.recipes/ad/movement/trusts" %}

{% embed url="https://medium.com/r3d-buck3t/breaking-domain-trusts-with-forged-trust-tickets-5f03fb71cd72" %}

{% embed url="https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}

{% embed url="https://attack.mitre.org/techniques/T1482/" %}

{% embed url="https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/attack-trusts" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/" %}

{% embed url="https://www.semperis.com/blog/ad-security-research-breaking-trust-transitivity/" %}

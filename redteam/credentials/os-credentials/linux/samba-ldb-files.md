# Samba LDB files

## Theory

A [Samba](https://wiki.samba.org/index.php/Samba_Security_Documentation) AD DC is Samba running the **Active Directory Domain Controller** role on Linux. In that mode, Samba is not just a file server: it also provides core AD services, including LDAP-backed directory services, a Kerberos KDC, and AD replication logic.

Internally, Samba stores AD data using [**LDB**](https://wiki.samba.org/index.php/LDB), which is Samba’s embedded LDAP-like database layer. For a Samba AD DC, two of the most important backend stores are **`sam.ldb`** and **`secrets.ldb`**. In practice, `sam.ldb` is the main AD directory database for the domain controller, while `secrets.ldb` is part of the local secret material used by the DC role.

That distinction matters. Broadly speaking:

* **`sam.ldb`** is the directory data store for the AD DC role: domain objects, attributes, metadata, and the AD-specific records Samba needs to behave like a DC. Samba documentation and code references show that provisioning, USN tracking, and AD database operations are tied to `sam.ldb`.
* **`secrets.ldb`** is a local secret store used by Samba components for sensitive DC-side material. Samba mailing-list discussions and hardening guidance treat it as part of the secret-bearing files in the `private/` area.

## Practice

If you already have **root on the Samba AD DC**, we can extract authentication artifacts directly from that storage layer.

{% tabs %}
{% tab title="samba-tool" %}
You can often use the native [samba-tool](https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html) to extract authentication artifacts equivalent to **NT hashes** and/or **Kerberos keys**

```bash
samba-tool user export /tmp/users.txt --attributes=uid,userPrincipalName,sAMAccountName,unicodePwd
```

{% hint style="info" %}
_These hashes look a bit different from what you’d expect from a Windows DC, but don’t worry — they’re still **NT hashes**. You can crack them just like you would with any other._
{% endhint %}
{% endtab %}

{% tab title="ldbsearch" %}
[ldbsearch ](https://linux.die.net/man/1/ldbsearch)searches a LDB database for records matching the specified expression. We can abuse it to extract sensitive artefacts

```bash
ldbsearch -H /var/lib/samba/private/sam.ldb '(objectClass=user)' sAMAccountName unicodePwd
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://infosecwriteups.com/samba-active-directory-domain-controller-linux-what-to-do-when-impacket-bloodhound-dont-work-1faee4828d5b" %}

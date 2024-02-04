---
description: 'MITRE ATT&CK™ Unsecured Credentials: Credentials In Files - Technique T1552.00'
---

# Credentials In Files

## Theory

We may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

## Practice

### Tools

{% tabs %}
{% tab title="Noseyparker" %}
[Noseyparker](https://github.com/praetorian-inc/noseyparker) is a command-line program that finds secrets and sensitive information in textual data and Git history. We can use this tool to recursively search sensitive information in a folder

```bash
# Scan filesystem / folder
noseyparker scan --datastore np.myDataStore /path/to/folder

# Get results
noseyparker report -d np.myDataStore
```

{% hint style="info" %}
You may use this tools to search sensitives files in a [mounted NFS share](../../../delivery/protocols/nfs.md#mount-nfs-shares), a [mounted SMB share](../../../delivery/protocols/smb.md#acls-of-shares-file-folder), or even [exiltrated data](../../../exfiltration/).
{% endhint %}
{% endtab %}
{% endtabs %}

### Hunting for config files

{% tabs %}
{% tab title="Windows" %}
[Dir](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir) command can be use to find configuration files by recursively searching files with a specific extension or name.

```powershell
# /s : Recursive search
# /b : Displays a bare list of directories and files, w/o additional information.
# Check for config/password related files
cd C:\folder\to\search\in
dir /s /b *pass* == *cred* == *vnc* == *.config*

# /A:H : display hidden files 
dir /A:H /s "c:\program files"

# Check Recycle.bin and SID Folder
dir /s \'$Recycle.Bin'

# Check for juicy extensions
cd C:\folder\to\search\in
dir /s /b *.txt == *.pdf == *.xls == *.xlsx == *.doc == *.docx == *.ini
```

Using [Get-ChildItem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-7.3) Powershell cmdlet, we may achieve the same actions

```powershell
# Files
Get-ChildItem -Force -Path c:\\ -Filter "*pass*" -Recurse 2>$null

# Directories
Get-ChildItem -Force -Path c:\\ -Directory -Filter "*pass*" -Recurse 2>$null

# Check Recycle.bin and SID Folder
Get-ChildItem -Force -Path \'$Recycle.Bin'

# Check for juicy extensions
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue
```
{% endtab %}

{% tab title="Unix-Like" %}
`find` command can be use to find configuration files by recursively searching files with a specific extension or name.

```bash
# Find all .conf files
find / -type f -name *.conf 2>/dev/null

# Find all files containing "pass"
find / -type f -name *pass* 2>/dev/null
```
{% endtab %}
{% endtabs %}

### Hunting for passwords

{% tabs %}
{% tab title="Windows" %}
[Find](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/find) command can be use to find passwords in files by recursively searching text patterns

```powershell
# /s: recursive search
# /i: Non case-sensitive search
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

# /p: Skips files with non-printable characters.
# /n: Prints the line number of each line that matches.
findstr /spin "password" *.*
findstr /spin "password" c:\Users\Administrator\*
```

We may find passwords in registries using the [reg](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg) command

```powershell
# Registry subkey information
# query: Returns a list of the next tier of subkeys and entries that are located under a specified subkey in the registry
# HKLM: The keyname of HKEY_LOCAL_MACHINE
# /f: Specifies the data or pattern to search for.
# /t: Specifies registry types to search.
# /s: Specifies to query all subkeys and value names recursively.
reg query HKLM /f password /t REG_SZ /s
```

Alternatively, we may find passwords in emails at the following locations

```
C:\Users\<username>\Documents\Outlook Files
C:\Users\<username>\AppData\Local\Microsoft\Outlook
```
{% endtab %}

{% tab title="Unix-Like" %}
The grep command can be use to find passwords in files by recursively searching text patterns.

```bash
cd /
grep -ari 'password'
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1552/001/" %}

{% embed url="https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/" %}

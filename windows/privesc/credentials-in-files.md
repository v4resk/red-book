---
description: >-
  MITRE ATT&CK™  Unsecured Credentials: Credentials In Files - Technique
  T1552.001
---

# Credentials In Files

## Theory

We may search for cleartext passwords in various files stored locally. There is chance that you find application or user passwords in text, notes or configuration files.&#x20;

## Practice

### Hunting for config files

{% tabs %}
{% tab title="Config Files" %}
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
{% endtabs %}

### Hunting for passwords

{% tabs %}
{% tab title="Passwords" %}
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
{% endtabs %}

## Resources

{% embed url="https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/" %}

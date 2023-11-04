---
description: 'MITRE ATT&CK™ Unsecured Credentials: Private Keys - T1552.004'
---

# SSH Private Keys

## Theory

We may search for SSH private key in publicly-exposed services (like webservers ore SMB shares) or in common directories if we gained access to the target.&#x20;

## Practice

### Find Private Keys

{% tabs %}
{% tab title="UNIX-like" %}
We may find SSH keys in all `.ssh` directories using the find command.

```bash
find / -type d -name *.ssh -printf '%p\n' -exec ls -l {} \; 2>/dev/null
```
{% endtab %}

{% tab title="Windows" %}
We may find SSH keys in `C:\Users\(username)\.ssh\` directories.

```powershell
dir C:\Users\(username)\.ssh\
```
{% endtab %}
{% endtabs %}

### Brute-Force Private Keys

{% tabs %}
{% tab title="Brute-Force" %}
First of all, you need to format the private key to make John to recognize it.

```bash
ssh2john private_key.txt > hash.txt
# or
python2 /usr/share/john/ssh2john.py private_key.txt > hash.txt
```

Crack the password of the private key using the formatted text.

```bash
#John
john --wordlist=wordlist.txt hash.txt
```
{% endtab %}
{% endtabs %}

---
description: >-
  MITRE ATT&CK™ OS Credential Dumping: /etc/passwd and /etc/shadow - Technique
  T1003.008
---

# Shadow File

## Theory

We may attempt to dump the contents of `/etc/passwd` and `/etc/shadow` to enable offline password cracking. Most modern Linux operating systems use a combination of `/etc/passwd` and `/etc/shadow` to store user account information including password hashes in `/etc/shadow`.&#x20;

{% hint style="info" %}
By default, `/etc/shadow` is only readable by the root user
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
If we can access **/etc/passwd** and **/etc/shadow** as well, we can crack user passwords using **unshadow** and **John The Ripper**.

We can use the unshadow command to combined the /etc/passwd and /etc/shadow files

```sh
unshadow passwd.txt shadow.txt > passwords.txt
```

Then, we can crack the hashes using john.

```sh
john --wordlist=wordlist.txt passwords.txt

# If the hash in /etc/shadow contains the $y$ prefix, specify the hash format to "crypt".
# btw, $ye$ is the scheme of the yescrypt.
john --format=crypt --wordlist=wordlist.txt passwords.txt
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1003/008/" %}

{% embed url="https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/#crack-user-passwords" %}

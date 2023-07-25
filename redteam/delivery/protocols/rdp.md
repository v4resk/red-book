---
description: Port 3389
---

# 🛠️ RDP

## Theory

**Remote Desktop** Protocol (**RDP**) is a proprietary protocol developed by Microsoft, which provides a user with a graphical interface to connect to another computer over a network connection. The user employs **RDP** client software for this purpose, while the other computer must run **RDP** server software.

## Practice

### Enumerate

{% tabs %}
{% tab title="Nmap" %}
We can use nmap to enumerate informations about the running RDP server

```bash
# Enum NetBIOS, DNS, and OS build version.
nmap -p 3389 --script rdp-ntlm-info <target>

# Enum available encryption and CredSSP (NLA)
nmap -p 3389 --script rdp-enum-encryption <target>
```
{% endtab %}
{% endtabs %}


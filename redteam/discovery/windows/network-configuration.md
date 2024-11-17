---
description: MITRE ATT&CK™ System Network Configuration Discovery - Technique T1016
---

# Network Configuration

## Theory

Understanding the target network configuration is a critical enumeration phase. Interfaces, routes, and active connections is pivotal for mapping out the network infrastructure and identifying potential points of entry or vulnerabilities.&#x20;

This section will explore key commands used to enumerate and gather crucial network information, providing insights into how these commands aid in assessing and understanding the network environment.

## Practice

### Routing Table

{% tabs %}
{% tab title="route" %}
The `route print` command may be used to display the routing table of a Windows system.

```powershell
route print
```
{% endtab %}
{% endtabs %}

### Network Interfaces

{% tabs %}
{% tab title="ipconfig" %}
`IPConfig` is a versatile command that provides comprehensive information about the network interfaces, IP addresses, subnet masks, DNS configuration, MAC addresses, and more.

```powershell
# Display network interface informations
ipconfig /all

# Display local DNS cache
ipconfig /all
```
{% endtab %}
{% endtabs %}

### Display Connections

{% tabs %}
{% tab title="netstat" %}
The `netstat` command may be used to displays active and listening network connections, including ports and associated processes.

```powershell
# Display all connections and ports with associated process ID
netstat -ano

# Display all connections and ports with associated process ID + executable involved
# Require admin rights
netstat -bano

# Display only listening ports
netstat -an | findstr LISTENING
```
{% endtab %}
{% endtabs %}

### **ARP Table**

{% tabs %}
{% tab title="arp" %}
The `arp` command in Windows can be used to display the ARP cache, which contains the mapping of IP addresses to MAC addresses within the local network. This command provides a list of known devices and their corresponding MAC addresses connected to the network.

```powershell
arp -a
```
{% endtab %}
{% endtabs %}

### NetBIOS Name Cache

{% tabs %}
{% tab title="nbtstat" %}
The `nbtstat` command may be used to displays the [NetBIOS](../../../network/protocols/nbt-ns-netbios.md) name table cache, listing the NetBIOS names and their corresponding IP addresses cached on the local system.

```powershell
nbtstat -c
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1016/" %}

---
description: MITRE ATT&CK™ Persistence - Tactic TA0003
---

# 🛠️ GSocket for Persistence

## Theory

[**GSocket**](https://github.com/hackerschoice/gsocket) is a networking utility designed to facilitate secure and transparent TCP connections between hosts, even when they are behind Network Address Translation (NAT) devices or firewalls. It achieves this by leveraging the **Global Socket Relay Network (GSRN)**, enabling seamless and encrypted communication without requiring direct IP address visibility.

**Key Features**:

* **Firewall and NAT Traversal**: GSocket allows connections between hosts without modifying firewall settings, making it ideal for environments with strict network controls.
* **End-to-End Encryption**: Utilizing OpenSSL's Secure Remote Password (SRP) protocol, GSocket ensures that all data transmitted between hosts is securely encrypted.  GSRN acts as an intermediary, forwarding encrypted traffic between endpoints.
* **No Fixed IPs**: Instead of a known destination address, each peer connects to GSRN and advertises itself using a **cryptographic identifier derived from the shared password**. Two machines using the same password can **automatically find each other** via GSRN, even if their IP addresses change.

These features make **GSocket** a powerful tool for establishing resilient persistence on compromised endpoints.

## Practice

{% tabs %}
{% tab title="Persistence Script" %}

{% endtab %}

{% tab title="Systemd Persistence" %}

{% endtab %}

{% tab title="SSH-Based Persistence" %}

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://github.com/hackerschoice/gsocket" %}

{% embed url="https://www.gsocket.io/" %}

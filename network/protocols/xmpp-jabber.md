---
description: Pentesting XMPP/Jabber - TCP Ports 5222, 5269, 8010
---

# XMPP/Jabber

## Theory

**Extensible Messaging and Presence** Protocol (XMPP, originally named **Jabber**) is an open communication protocol designed for instant messaging (IM), presence information, and contact list maintenance. Based on XML (Extensible Markup Language), it enables the near-real-time exchange of structured data between two or more network entities. The service usually run over ports **TCP 5222, 5269 or 8010**

## Practice

### Connect to a XMPP server

{% tabs %}
{% tab title="Pidgin" %}
[Pidgin](https://pidgin.im/install/) is a chat program that allows to connect to multiple chat networks, including XMPP servers.

<figure><img src="../../.gitbook/assets/image (15).png" alt="" width="453"><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

### Openfire <a href="#firstheading" id="firstheading"></a>

Openfire is an instant messaging (IM) and groupchat server for the Extensible Messaging and Presence Protocol (XMPP) written in Java.

#### CVE-2023-32315 - Authentication Bypass Vulnerability

{% tabs %}
{% tab title="Exploit" %}
**CVE-2023-32315** is a path traversal vulnerability found in the web-based Admin Console of Openfire. This security flaw enables unauthenticated users to access restricted pages that are meant exclusively for administrative use within a configured Openfire environment. **Successful exploitation of this vulnerability allows an attacker to create a new administrative user**.

This vulnerability impacts all Openfire versions released after April 2015, commencing from version **3.10.0.** The issue has been patched in releases **4.7.5** and **4.6.8**.

The [CVE-2023-32315](https://github.com/miko550/CVE-2023-32315) python script allow to exploit this vulnerability

```
python3 CVE-2023-32315.py -t http://127.0.0.1:9090
python3 CVE-2023-32315.py -l lists.txt
```
{% endtab %}
{% endtabs %}

#### Remote Code Execution (RCE)

{% tabs %}
{% tab title="plugin" %}
If you have administrator access to the Openfire console, you can achieve remote code execution by deploying a web shell through a plugin upload. To do this, follow these steps:

1. go to tab plugin > upload plugin [openfire-management-tool-plugin.jar](https://github.com/miko550/CVE-2023-32315/raw/main/openfire-management-tool-plugin.jar)
2. go to tab server > server settings > Management tool
3. Access the websehll with password "123"
4. We should now be able to execute commands

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-voip#voip-basic-information" %}

{% embed url="https://en.wikipedia.org/wiki/XMPP" %}

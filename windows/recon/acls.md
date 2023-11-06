---
description: MITRE ATT&CK™ File and Directory Discovery - Technique T1083
---

# FIle/Folder ACLs

## Theory

An Access Control List (ACL) consists of Access Control Entries (ACEs), each specifying access rights for a trustee. There are two main types of ACLs within a security descriptor for a securable object: the Discretionary Access Control List (DACL) and the System Access Control List (SACL).

* **Discretionary Access Control List (DACL):** The DACL identifies trustees permitted or denied access to a securable object.&#x20;
* **System Access Control List (SACL):** The SACL permits administrators to record access attempts to secured objects.&#x20;

Understanding the compromised machine's characteristics is essential. Enumerating File and Folder ACLs is critical part of this process. This process includes investigating who has access to critical files, what level of access is granted, and whether there are misconfigured permissions that could potentially lead to unauthorized access, data leakage, or privilege escalation.

## Practice

### Find Writable Files/Folders

{% tabs %}
{% tab title="Powershell" %}
We can find all writable folders and files for our current user using the following command

```powershell
Get-ChildItem "c:\" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $fileName = $_.FullName; $acls = Get-Acl $fileName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Access | Where-Object { $_.FileSystemRights -match "Full|Modify|Write" -and $_.IdentityReference -match "Authenticated Users|Everyone|$env:username" }; if ($acls -ne $null) { [pscustomobject]@{ filename = $fileName; user = $acls | Select-Object -ExpandProperty IdentityReference } } } 2>$null |fl
```
{% endtab %}

{% tab title="cmd" %}
UKNOWN
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists" %}

{% embed url="https://attack.mitre.org/techniques/T1083/" %}

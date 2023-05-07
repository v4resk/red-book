---
description: MITRE ATT&CK™  Hijack Execution Flow - Technique T1574
---

# Insecure Services

## Theory
Microsoft Windows offers a wide range of fine-grained permissions and privileges for controlling access to Windows components including services. We can take advantage of missconfiguration to elevate our privileges.

## Practice

To get a list of all services, we can use following commands:
```
net start
wmic service list brief
sc query
Get-Service
```
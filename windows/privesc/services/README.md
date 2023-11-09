---
description: MITRE ATT&CK™  Hijack Execution Flow - Technique T1574
---

# Insecure Services

## Theory

One of the basic features of Microsoft Windows is the ability to run services. These are background processes, similar to Unix deamons. They are managed by the [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager). If they are misconfigured, as they usually run as a local system account, they can lead to privilege escalation.

## Practice

### Enumerate

{% content-ref url="../../recon/processes-and-services.md" %}
[processes-and-services.md](../../recon/processes-and-services.md)
{% endcontent-ref %}

### Exploit

{% content-ref url="weak-service-permissions.md" %}
[weak-service-permissions.md](weak-service-permissions.md)
{% endcontent-ref %}

{% content-ref url="weak-files-permissions.md" %}
[weak-files-permissions.md](weak-files-permissions.md)
{% endcontent-ref %}

{% content-ref url="weak-registry-permissions.md" %}
[weak-registry-permissions.md](weak-registry-permissions.md)
{% endcontent-ref %}

{% content-ref url="unquoted-service-path.md" %}
[unquoted-service-path.md](unquoted-service-path.md)
{% endcontent-ref %}

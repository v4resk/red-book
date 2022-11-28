# AMSI Bypass

## Theory

With the release of PowerShell, Microsoft released [AMSI (Anti-Malware Scan Interface)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal). It is a runtime detection measure shipped natively with Windows and is an interface for other products and solutions.

### How it works ?

AMSI (Anti-Malware Scan Interface) is a PowerShell security feature that will allow any applications or services to integrate directly into anti-malware products. Defender instruments AMSI to scan payloads and scripts before execution inside the .NET runtime. The [CLR (Common Language Runtime)](https://learn.microsoft.com/en-us/dotnet/standard/clr) and [DLR (Dynamic Language Runtime)](https://learn.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/dynamic-language-runtime-overview) are the runtimes for .NET.  
  
AMSI is fully integrated into the following Windows components:  
    - User Account Control, or UAC  
    - PowerShell  
    - Windows Script Host (wscript and cscript)  
    - JavaScript and VBScript  
    - Office VBA macros  
  
The below diagram depicts how data is dissected as it flows through the layers and what DLLs/API calls are being instrumented.  
![](http://hack-army.net/wp-content/uploads/2022/11/35e16d45ce27145fcdf231fdb8dcb35e.png)  
  
This is important to understand the complete model of AMSI, but we can break it down into core components, shown in the diagram below.  
![](http://hack-army.net/wp-content/uploads/2022/11/efca9438e858f0476a4ffd777c36501a.png)


{% hint style="danger" %}
Note: AMSI is only instrumented when loaded from memory when executed from the CLR. It is assumed that if on disk MsMpEng.exe (Windows Defender) is already being instrumented.
{% endhint %}

## Practice

To find where AMSI is instrumented, we can use [InsecurePowerShell](https://github.com/cobbr/InsecurePowerShell) maintained by [Cobbr](https://github.com/cobbr) which is a GitHub fork of PowerShell with security feature removed, and compare it with an [offical PowerShell GitHub](https://github.com/PowerShell/PowerShell).

### PowerShell Downgrade
The PowerShell downgrade attack is a very low-hanging fruit that allows attackers to modify the current PowerShell version to remove security features.  
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
Reflection allows a user or administrator to access and interact with .NET assemblies. It can be abused to modify and identify information from valuable DLLs.  
The AMSI utilities for PowerShell are stored in the **AMSIUtils** .NET assembly located in **System.Management.Automation.AmsiUtils**.

{% tabs %}
{% tab title="Powershell" %}
Matt Graeber published a one-liner to accomplish the goal of using Reflection to modify and bypass the AMSI utility. This one-line can be seen in the code block below.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```  
{% endtab %}
{% endtabs %}  

## References

{% embed url="https://tryhackme.com/room/runtimedetectionevasion" %}


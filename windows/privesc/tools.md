# Tools ⚙️

## Theory

On this page, we'll look at some automated tools we can use to enumerate privilege escalation vectors. These tools can be very useful because of their efficiency, speed and complete coverage. However, using such tools can significantly reduce our OpSec as it can be a very noisy process.

## Practice

{% tabs %}
{% tab title="winPEAS" %}
[winPEAS (Windows Privilege Escalation Awesome Scripts)](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) is a powerful and widely used privilege escalation tool to identify security weaknesses and privilege escalation vectors within Windows environments.

```powershell
# Executables
.\winPEASx64.exe
.\winPEASx86.exe 

# Powershell
Import-Module .\winPEAS.ps1
Start-ACLCheck
```
{% endtab %}

{% tab title="PowerUp" %}
[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```
{% endtab %}

{% tab title="JAWS" %}
[JAWS](https://github.com/411Hall/JAWS) is a PowerShell script designed to quickly identify potential privilege escalation vectors on Windows systems.

```powershell
.\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt
```
{% endtab %}

{% tab title="Watson" %}
[Watson](https://github.com/rasta-mouse/Watson) is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.

```powershell
.\WatsonNet3.5AnyCPU.exe
```

{% hint style="info" %}
Precompiled binaries can be found [here](https://github.com/carlospolop/winPE/tree/master/binaries/watson).
{% endhint %}
{% endtab %}

{% tab title="Sherlock" %}
[Sherlock](https://github.com/rasta-mouse/Sherlock) is a PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.

```powershell
Import-Module .\Sherlock.ps1
Find-AllVulns
```

{% hint style="info" %}
Sherlock has been deprecated and replaced by Watson, but can still be relevant.
{% endhint %}
{% endtab %}
{% endtabs %}

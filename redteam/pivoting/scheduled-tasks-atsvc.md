# Scheduled Tasks (ATSVC)

## Theory

Windows scheduled tasks can also be leveraged to run arbitrary commands since they execute a command when started. When using schtasks, it will try to connect to the Microsoft AT-Scheduler Service (ATSVC) remote service program through RPC in several ways:

* By using [MS-TSCH](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-tsch/cf7d3ced-70f2-4c7e-802e-93d4dfb7d089) protocols over RPC to connect EMP at port 135. WIll ask for the ATSVC RPC Endpoint wich is a dynamic port
* Try to reach ATSVC Through SMB named pipes (\PIPE\atsvc) on port 445 (SMB) or 139 (SMB over NetBIOS)

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) can be used to interact with Scheduled Tasks.

```bash
#Remotely exec a scheduled command 
atexec.py <domain>/<username>:<password>@<target> "whoami"
```
{% endtab %}

{% tab title="Windows" %}
On windows, we can use the built in schtasks.exe binary to remotely interact with services

```bash
#Remotely schedule a Task
schtasks /s TARGET /RU "SYSTEM" /create /tn "MyTask" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

#Remotely Run It 
schtasks /s TARGET /run /TN "MyTask" 

#Remotely Delete a Task
schtasks /S TARGET /TN "MyTask" /DELETE /F
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/lateralmovementandpivoting" %}

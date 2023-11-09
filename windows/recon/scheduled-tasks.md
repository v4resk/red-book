# Scheduled Tasks

## Theory

In Windows, the [Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) service allows to run automated tasks on a chosen computer. The tasks are used to run programms when a specific trigger occurs. Triggers work like conditions, triggering the execution of one or more actions when they are met. For example, a trigger can be temporal, linked to a particular date, launched when the system starts up, when the user logs on or in response to a Windows event.

If its misconfigured, it can be an interesting vector for privilege escalation. At the enumeration stage we are interested into following Scheduled Tasks parameters:

* The "Run As User" (i.e under which user the task will run)
* The Trigger (i.e when the task will be run)
* The task to be run (i.e what will be executed by this task)

## Practice

{% tabs %}
{% tab title="PowerShell" %}
To enumerate scheduled tasks, we may use following PowerShell commands.

```powershell
Get-ScheduledTask
```
{% endtab %}

{% tab title="CMD" %}
The command `schtasks` can be used to enumerate scheduled tasks from a cmd.

```powershell
schtasks /query /fo LIST /v
```
{% endtab %}
{% endtabs %}

# Insecure Scheduled Tasks

## Theory

In Windows, the [Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) service allows to run automated tasks on a chosen computer. The tasks are used to run programms when a specific trigger occurs. Triggers work like conditions, triggering the execution of one or more actions when they are met. For example, a trigger can be temporal, linked to a particular date, launched when the system starts up, when the user logs on or in response to a Windows event.

If its misconfigured, it can be an interesting vector for privilege escalation.

## Practice

### Enumerate

{% content-ref url="../../../discovery/recon/scheduled-tasks.md" %}
[scheduled-tasks.md](../../../discovery/recon/scheduled-tasks.md)
{% endcontent-ref %}

### Exploit

{% content-ref url="weak-file-folder-permissions.md" %}
[weak-file-folder-permissions.md](weak-file-folder-permissions.md)
{% endcontent-ref %}

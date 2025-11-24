# Windows Sysinternals

## Theory

[Windows Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) is a set of tools and advanced system utilities developed to help IT professionals manage, troubleshoot, and diagnose the Windows operating system in various advanced topics.

While built-in and Sysinternals tools are helpful for system administrators, these tools are also used by hackers, malware, and pentesters due to the inherent trust they have within the operating system. This trust is beneficial to Red teamers, who do not want to get detected or caught by any security control on the target system. Therefore, these tools have been used to evade detection and other blue team controls.

Sysinternals Suite is divided into various categories, including:

* Disk management
* Process management
* Networking tools
* System information
* Security tools<br>

## Practice

The following are some popular Windows Sysinternals tools:

| <p><a href="https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk">AccessChk</a><br></p>   | <p>Helps system administrators check specified access for files, directories, Registry keys, global objects, and Windows services.<br></p> |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| <p><a href="https://docs.microsoft.com/en-us/sysinternals/downloads/psexec">PsExec</a><br></p>         | <p>A tool that executes programs on a remote system.<br></p>                                                                               |
| <p><a href="https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer">ADExplorer</a><br></p> | <p>An advanced Active Directory tool that helps to easily view and manage the AD database.<br></p>                                         |
| <p><a href="https://docs.microsoft.com/en-us/sysinternals/downloads/procdump">ProcDump</a><br></p>     | <p>Monitors running processes for CPU spikes and the ability to dump memory for further analysis.<br></p>                                  |
| <p><a href="https://docs.microsoft.com/en-us/sysinternals/downloads/procmon">ProcMon</a><br></p>       | An essential tool for process monitoring.                                                                                                  |
| [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)                             | A tool that lists all TCP and UDP connections.                                                                                             |
| [PsTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)                             | The first tool designed in the Sysinternals suite to help list detailed information.                                                       |
| [Portmon](https://docs.microsoft.com/en-us/sysinternals/downloads/portmon)                             | <p>Monitors and displays all serial and parallel port activity on a system.<br></p>                                                        |
| [Whois](https://docs.microsoft.com/en-us/sysinternals/downloads/whois)                                 | Provides information for a specified domain name or IP address.                                                                            |

{% hint style="danger" %}
In order to use the Windows Sysinternals tools, we need to accept the Microsoft license agreement of these tools. We can do this by passing the \*\*-accepteula\* argument at the command prompt or by GUI during tool execution.
{% endhint %}

### Sysinternals Live

One of the great features of Windows Sysinternals is that there is no installation required. Microsoft provides a Windows Sysinternals service, Sysinternals live, with various ways to use and execute the tools. We can access and use them through:

* Web browser ([link](https://live.sysinternals.com/)).
* Windows Share
* Command prompt

Use it by entering the Sysinternal Live path `\\live.sysinternals.com\tools`

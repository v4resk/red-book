# DCOM

## Theory

**DCOM** (Distributed Component Object Model) objects are **interesting** due to the ability to **interact** with the objects **over the network**. Microsoft has some good documentation on DCOM [here](https://msdn.microsoft.com/en-us/library/cc226801.aspx) and on COM [here](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). You can find a solid list of DCOM applications using PowerShell, by running `Get-CimInstance Win32_DCOMApplication`.

**DCOM** (Distributed Component Object Model) Remote Protocol, exposes application objects via remote procedure calls (RPCs) and consists of a set of extensions layered on the Microsoft Remote Procedure Call Extensions. We can leverage some functions exposed by **MMC20.Application**, **ShellWindows** and **ShellBrowserWindow** COM objects to execute arbitrary code on remote targets.

## Practice

### Dcomexec.py

{% tabs %}
{% tab title="UNIX-like" %}
Impacket's [dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py) scriot can be use to spawn a semi-interactive shell. It can leverage **MMC20.Application**, **ShellWindows** and **ShellBrowserWindow** objects.

```bash
#semi-interactive shell
dcomexec.py domain/user:password@IP <command>

#semi-interactive shell using ShellWindows object
# -object [{ShellWindows,ShellBrowserWindow,MMC20}]
dcomexec.py domain/user:password@IP -object ShellWindows <command>

#semi-interactive shell with powershell command processor
dcomexec.py domain/user:password@IP -shell-type powershell <command> 
```
{% endtab %}
{% endtabs %}

### MMC20.Application

The [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COM object allows you to script components of MMC snap-in operations. The`ExecuteShellCommand`  method under Document.ActiveView can be abuse to execute arbitrary commands on remote target.

{% tabs %}
{% tab title="Windows - Powershell" %}

{% endtab %}

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}

### ShellWindows&#x20;

### ShellBrowserWindow

## Resources



{% embed url="https://www.ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model" %}

{% embed url="https://book.hacktricks.xyz/windows-hardening/lateral-movement/dcom-exec" %}

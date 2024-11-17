# Knowing your Shell

## Theory

Upon gaining access to a Windows target, such as after exploiting a [command injection vulnerability](../../../web-pentesting/web-vulnerabilities/server-side/command-injection.md) in a web service, the exact type of shell might not always be immediately evident. This section delves into specific tricks to discern the type of shell (CMD or PowerShell) and even determine the architecture of the process (x32 or x64).&#x20;

Understanding these aspects is crucial, especially when tailoring specific techniques, payloads , or powershell exploits for successful execution.

## Practice

### **Detecting Shell Type**

{% tabs %}
{% tab title="Detecting" %}
To detect whether the current shell is CMD or PowerShell, a simple trick can be employed. Executing the following command:

```powershell
# Echo whether the current shell is CMD or PowerShell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
{% endtab %}
{% endtabs %}

### **Detecting PowerShell Architecture:**

{% tabs %}
{% tab title="Detecting" %}
identifying the architecture of PowerShell being used (whether it's 32-bit or 64-bit) holds significance in certain scenarios, such when dealing with powershell exploits.

The following command will outputs a Boolean value, indicating whether the current PowerShell process is running in a 64-bit environment.

```powershell
[Environment]::Is64BitProcess
```
{% endtab %}
{% endtabs %}

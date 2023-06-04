# .NET Deserialization

## Theory

Insecure deserialization is a vulnerability that can affect applications built using the .NET framework. They occurs when the deserialization process is not properly secured and validated, allowing attackers to exploit it and execute arbitrary code or perform other malicious activities.

## Practice

### JSON.NET Deserialization

In .NET application that uses JSON.net (Newtonsoft library), we can inject arbitrary code or read local files by abusing JSON deserialization objects.

{% tabs %}
{% tab title="Enumerate" %}
To decompile a .NET application you can use [dnSpy](https://github.com/dnSpy/dnSpy) on windows or [AvaloniaILSpy](https://github.com/icsharpcode/AvaloniaILSpy) on Linux

If the application have the [TypeNameHandling](https://www.newtonsoft.com/json/help/html/T\_Newtonsoft\_Json\_TypeNameHandling.htm) not being set to `None` and deserialize a parameter without proper validation, it is vulnerable.

```csharp
json = JsonConvert.DeserializeObject<Example>(json);We can give the Json value to the “JsonConvert.DeserializeObject(json)” with a reserved key ($type).
The format is as follow. The value of $type is a string that contains the assembly-qualified name of the .NET type to be deserialized.
```

{% hint style="info" %}
In the previous code, `Example` is the class to what json data will be converted (deserialized)
{% endhint %}
{% endtab %}

{% tab title="Payloads" %}
We can give the Json value to the “JsonConvert.DeserializeObject(json)” with a reserved key (**`$type`**).\
The format is as follow. The value of **`$type`** is a string that contains the assembly-qualified name of the .NET type to be deserialized.

```json
{
	"$type": "<namespace>.<class>, <assembly>",
	"<method_name>": "<attribute>"
}
```
{% endtab %}

{% tab title="Tools" %}
We can use [ysoserial.net](https://github.com/pwntester/ysoserial.net) (windows) to generate payloads.&#x20;

```powershell
#Raw output
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "id"

#Base64 output
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "id" -o base64
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization" %}

{% embed url="https://exploit-notes.hdks.org/exploit/web/security-risk/json-net-deserialization/" %}

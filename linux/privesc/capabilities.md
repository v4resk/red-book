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

{% tabs %}
{% tab title="Enumerate" %}
BLANK
{% endtab %}

{% tab title="Exploit" %}
BLANK
{% endtab %}
{% endtabs %}

## References

{% embed url="https://blog.ploetzli.ch/2014/understanding-linux-capabilities/" %}
{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities" %}
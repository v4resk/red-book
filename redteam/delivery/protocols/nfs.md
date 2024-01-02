---
description: Port TCP/UDP 2049
---

# NFS

## Theory

NFS is a distributed file system protocol that allows a user on a client computer to access files over a computer network much like local storage is accessed. Default ports are [111 (RPC Port Mapper)](rpc-port-mapper.md) and 2049.

The NFS protocol has **no mechanism for authentication** or **authorization**. The authorization is taken from the available information of the file system where the server is responsible for translating the **user information** supplied by the **client** to that of the **file system** and converting the corresponding authorization information as correctly as possible into the syntax required by UNIX.

## Practice

### Enumeration

{% tabs %}
{% tab title="nmap" %}
Following nmap scripts can be used to enumerate a NFS server

```bash
nmap --script=nfs-ls,nfs-statfs,nfs-showmount -p 111,2049 <target-ip>
```
{% endtab %}
{% endtabs %}

### Enumerate NFS Shares / Mount points

To know **which folder** has the server **available** to mount you can use following commands and modules

{% tabs %}
{% tab title="showmount" %}
```bash
showmount -e <IP>
```
{% endtab %}

{% tab title="Metasploit" %}
This metasploit module can Scan NFS mounts and list permissions

```bash
msf5> use scanner/nfs/nfsmount
```
{% endtab %}
{% endtabs %}

### Mount NFS Shares

If we find a folder available, we can mount it to local folder.

{% tabs %}
{% tab title="mount" %}
Create a new folder under **/mnt**

```bash
sudo mkdir /mnt/NsfShare
```

Now mount the folder

```bash
# -t: Type
# -o nolock: Option. 'nolock' disables file locking. It's required for older NFS servers.
sudo mount -t nfs <target-ip>:/target/dir /mnt/test -o nolock

# -o vers=2: 
sudo mount -t nfs <target-ip>:/target/dir /mnt/test -o nolock -o vers=2
```

To confirm or unmount shares, you can use following commands

```bash
# Confirm mounting successfully
ls /mnt/test

# Clean up the mounted folder
sudo umount /mnt/test
sudo rm -r /mnt/test
```
{% endtab %}
{% endtabs %}

### Permissions

The most common **authentication is via UNIX `UID`/`GID` and `group memberships`**, which is why this syntax is most likely to be applied to the NFS protocol. One problem is that the **client** and **server** do **not necessarily** have to have the **same mappings of UID/GID** to users and groups. No further checks can be made on the part of the server. This is why NFS should **only** be used with this authentication method in **trusted networks**.

If you mount a folder which contains **files or folders only accesible by some user** (by **UID**). You can **create** **locally** a user with that **UID** and using that **user** you will be able to **access** the file/folder.

### Config files & settings

The NFS server configuration can be found in its local files

```bash
/etc/exports
/etc/lib/nfs/etab
```

Some settings can be dangerous and even allow local privileges escalation:

| Option           | Description                                                                                                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rw`             | Read and write permissions.                                                                                                                                                      |
| `insecure`       | Ports above 1024 will be used. in secure mode, forces the client to communicate using a port below 1024, hence proving they are root                                             |
| `nohide`         | If another file system was mounted below an exported directory, this directory is exported by its own exports entry.                                                             |
| `no_root_squash` | All files created by root are kept with the UID/GID 0. See[ this page](../../privilege-escalation/privesc-1/nfs-no\_root\_squash-no\_all\_squash.md).                            |
| `no_all_squash`  | This is similar to **no\_root\_squash** option but applies to **non-root users.** See [this page](../../privilege-escalation/privesc-1/nfs-no\_root\_squash-no\_all\_squash.md). |

### Local Privilege Escalation

We can abuse the no\_root\_squash and no\_all\_squash NFS configurations, as explained on this page.

{% content-ref url="../../privilege-escalation/privesc-1/nfs-no_root_squash-no_all_squash.md" %}
[nfs-no\_root\_squash-no\_all\_squash.md](../../privilege-escalation/privesc-1/nfs-no\_root\_squash-no\_all\_squash.md)
{% endcontent-ref %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting" %}

{% embed url="https://exploit-notes.hdks.org/exploit/network/protocol/nfs-pentesting/" %}

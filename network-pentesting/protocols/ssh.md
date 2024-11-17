---
description: Port TCP 22
---

# SSH

## Theory

SSH or Secure Shell or Secure Socket Shell, is a network protocol that gives users a secure way to access a computer over an unsecured network.

SHH protocol operate by default on **TCP port 22**

## Practice

### Enumerate SSH server

{% tabs %}
{% tab title="Nmap" %}
We can use nmap to enumerate informations about the running SSH server

```bash
# Send default nmap scripts for SSH and retreive version
nmap -p22 <ip> -sC -sV

# Send all nmap ssh related scripts
nmap -p22 <ip> --script ssh-*

# Retrieve supported algorythms 
nmap -p22 <ip> --script ssh2-enum-algos

# Retrieve weak keys
nmap -p22 <ip> --script ssh-hostkey --script-args ssh_hostkey=full

# Check authentication methods for an user
nmap -p22 <ip> --script ssh-auth-methods --script-args="ssh.user=root"
```
{% endtab %}

{% tab title="Netcat" %}
We can use Netcat to enumerate the SSH server banner

```bash
nc -vn <IP> 22
```
{% endtab %}

{% tab title="ssh-audit" %}
[ssh-audit](https://github.com/jtesta/ssh-audit) (python) may be used for ssh server & client configuration auditing.

```bash
#Basic audit
python ssh-audit.py <IP>
```
{% endtab %}
{% endtabs %}

### Enumerate Users

{% tabs %}
{% tab title="Metasploit" %}
In some versions of OpenSSH you can make a timing attack to enumerate users. You can use a metasploit module in order to exploit this:

```bash
msfconsole
msf> use auxiliary/scanner/ssh/ssh_enumusers
```
{% endtab %}
{% endtabs %}

### Brute-Force Credentials

{% hint style="info" %}
If the target host opens port 80 or 443, you can generate [wordlist from the contents of the website](../../redteam/credentials/passwd/generate-wordlists.md#cewl) then use it with your tool.
{% endhint %}

{% tabs %}
{% tab title="Hydra" %}
When bruteforcing accounts, you may lock accounts

```bash
# -t : Number of tasks
# -L/l : username list / username 
# -P/p : password list / password
hydra -l username -P passwords.txt <target-ip> ssh -t 4
hydra -L usernames.txt -p password <target-ip> ssh -t 4

# -s : Specific port
hydra -l username -P passwords.txt -s 2222 <target-ip> ssh -t 4
hydra -l username -P passwords.txt ssh://<target-ip>:2222 -t 4
```
{% endtab %}
{% endtabs %}

### Crack SSH Private Key

Some private keys require a password or passphrase for operation, so we may attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase [off-line](../../redteam/credentials/passwd/brute-force/offline-password-cracking.md).

{% content-ref url="../../redteam/credentials/unsecured-credentials/ssh-private-keys.md" %}
[ssh-private-keys.md](../../redteam/credentials/unsecured-credentials/ssh-private-keys.md)
{% endcontent-ref %}

### Persistence

It's possible to backdoor an SSH public key using the `command=` argument. The backdoor will execute whenever the user logs in using this key.

{% content-ref url="../../redteam/persistence/linux/ssh.md" %}
[ssh.md](../../redteam/persistence/linux/ssh.md)
{% endcontent-ref %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh" %}

{% embed url="https://exploit-notes.hdks.org/exploit/network/protocol/ssh-pentesting" %}

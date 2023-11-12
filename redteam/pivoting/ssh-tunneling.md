---
description: MITRE ATT&CK™ Protocol Tunneling  - Technique T1572
---

# SSH Tunneling

## Theory

SSH tunneling, also known as "SSH port forwarding," is a method that uses the secure shell (SSH) protocol to create encrypted tunnels for network connections. SSH tunneling may be used for covert communication and circumventing network security measures.

## Practice

### SSH Port Forwarding

By using a SSH client with an OpenSSH server, it's possible to create both forward and reverse connections to make SSH tunnels, allowing us to forward ports, and/or create proxies.

{% content-ref url="portfwd.md" %}
[portfwd.md](portfwd.md)
{% endcontent-ref %}

### Sshuttle

[**Sshuttle**](https://github.com/sshuttle/sshuttle) uses an SSH connection to create a tunnelled proxy that acts like a new interface. In short, it simulates a VPN, allowing us to route our traffic through the proxy. As it creates a tunnel through SSH, anything we send through the tunnel is also encrypted.

{% tabs %}
{% tab title="Tunnel to Host" %}
We can create our tunnelled proxy by connecting with schuttle to the compromised host's SSH server.

```bash
# Create Tunnel
# SUBNET: specify your subnet (e.g 172.16.0.0/24)
sshuttle -r <USER>@<TARGET_IP> <SUBNET>

# Automatically determine the subnets
sshuttle -r <USER>@<TARGET_IP> -N

# Exclude the specific ip (-x)
sshuttle -r <USER>@<TARGET_IP> <SUBNET> -x <remote-ip>
```

If you don't know the user's password but have an SSH Key, we may use following command

```bash
sshuttle -r <USER>@<TARGET_IP> --ssh-cmd "ssh -i KEYFILE" <SUBNET>
```

{% hint style="danger" %}
If you get the error "Failed to flush caches: Unit dbus-org.freedesktop.resolve1.service not found...", you need to flush DNS cache.

```bash
sudo systemctl enable systemd-resolved.service
sudo resolvectl flush-caches
```

Run sshuttle again.
{% endhint %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/wreath" %}

{% embed url="https://exploit-notes.hdks.org/exploit/network/protocol/ssh-pentesting/#sshuttle" %}

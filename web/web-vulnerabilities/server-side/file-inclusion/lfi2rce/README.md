# LFI to RCE

## Theory

Local File Inclusion (LFI) refers to a vulnerability in web applications where an attacker can manipulate input parameters to include local files on the server. By exploiting this vulnerability, the attacker can access sensitive files stored on the server, such as configuration files or even **execute arbitrary code**.

## Practice

{% hint style="info" %}
In PHP, vulnerable functions are: `require`, `require_once`, `include`, `include_once`
{% endhint %}


## References

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion" %}

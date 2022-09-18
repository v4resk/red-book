# Logon Triggered Persistence 

## Theory
It's sometime usefull to know how to plant payloads that will get executed when a user logs into the system ! 

## Practice

{% tabs %}

{% tab title="Startup Folders" %}
We can put executable in each user's folder:  
- `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`  
  
If we want to force all users to run a payload while logging in, we can use the folder under:  
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`  
{% endtab %}

{% tab title="Registry" %}
You can also force a user to execute a program on logon via the registry. You can use the following registry entries to specify applications to run at logon:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`  
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`  
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`  
  
For example:
```bash
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v PeMalware /t REG_SZ /d "C:\Users\user1\shell.exe"
```


{% hint style="success" %}
Registry entries under `HKCU` will only apply to the current user.  
Registry entries under `HKLM` will apply to everyone.
{% endhint %}
{% endtab %}

{% tab title="WinLogon" %}
Winlogon, the Windows component that loads your user profile right after authentication can be abuse for persistence  
We can edit the `Shell` & `Userinit` keys:  

{% hint style="danger" %}
If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, you can append commands separated by a comma, and Winlogon will process them all.
{% endhint %}
  
```bash
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "C:\Windows\System32\Userinit.exe, C:\Windows\shell.exe" /f
```
{% endtab %}

{% tab title="Logon Scripts" %}
One of the things userinit.exe does while loading your user profile is to check for an environment variable called `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine.  

```bash
reg add "HKCU\Environment" /v UserInitMprLogonScript /d "C:\Windows\shell.exe" /f
```

{% endtab %}


{% endtabs %}

# Logon Triggered Persistence 

## Theory
It's sometime usefull to know how to plant payloads that will get executed when a user logs into the system.

{% tabs %}

{% tab title="Startup Folders" %}
We can put executable in each user's folder: `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`  
If we want to force all users to run a payload while logging in, we can use the folder under: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`  
{% endtab %}

{% tab title="Registry" %}
You can also force a user to execute a program on logon via the registry. You can use the following registry entries to specify applications to run at logon:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

{% hint style="success" %}
Registry entries under `HKCU` will only apply to the current user.  
Registry entries under `HKLM` will apply to everyone.  
{% endhint %}

{% endtab %}

{% endtabs %}

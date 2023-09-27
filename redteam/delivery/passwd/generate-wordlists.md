# Generate Wordlists

## Theory

Having a good wordlist is critical to carrying out a successful password attack. It is important to know how you can generate username lists and password lists. In this section, we will discuss creating targeted username and password lists.

## Practice

### Generate a Wordlist

{% tabs %}
{% tab title="CeWL" %}
Tools such as [Cewl - Custom Word List generator](https://github.com/digininja/CeWL) can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to **generate a wordlist specific to a given company or target**.

CeWL is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links.

```bash
cewl -w list.txt -d 5 -m 5 http://target.net
```
{% endtab %}

{% tab title="User List" %}
Gathering employees' names in the enumeration stage is essential. We can generate username lists from the target's website. For the following example, we'll assume we have a {first name} {last name} (ex: John Smith) and a method of generating usernames.

Thankfully, there is a tool [username\_generator](https://github.com/therodri2/username\_generator.git) that could help create a list with most of the possible combinations if we have a first name and last name.

```bash
python3 username_generator.py -w users.lst
```
{% endtab %}

{% tab title="Crunch" %}
[Crunch](https://github.com/jim3ma/crunch) is one of many powerful tools for creating an offline wordlist. With crunch, we can specify numerous options, including min, max, and options

```bash
#min=2 max=2 charset=01234abcd outfile=crunch.txt
crunch 2 2 01234abcd -o crunch.txt
```

Crunch also lets us specify a character set using the -t option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:

`@` - lower case alpha characters

`,` - upper case alpha characters

`%` - numeric characters

`^` - special characters including space

```bash
#min=6 max=6 option=pass[0-9][0-9] outfile=stdin
crunch 6 6 -t pass%%
```
{% endtab %}

{% tab title="CUPP - OSINT" %}
[CUPP - Common User Passwords Profiler](https://github.com/Mebus/cupp) is an automatic and interactive tool written in Python for creating custom wordlists. For instance, if you know some details about a specific target, such as their birthdate, pet name, company name, etc., this could be a helpful tool to generate passwords based on this known information.

```bash
#Interactive mod
python3 cupp.py -i

#Pre-created wordlists
python3 cupp.py -l

# Alecto database default logins
python3 cupp.py -a
```
{% endtab %}

{% tab title="LDAPWordlistHarvester" %}
[LDAPWordlistHarvester](https://github.com/p0dalirius/LDAPWordlistHarvester) is an other greate tool from [p0dalirius](https://github.com/p0dalirius). It generates a wordlist from the information present in [LDAP](../protocols/ldap.md), in order to crack passwords of domain accounts.

```bash
./LDAPWordlistHarvester.py -d 'domain.local' -u 'Administrator' -p 'P@ssw0rd123!' --dc-ip 192.168.1.101
```
{% endtab %}
{% endtabs %}

### Rules-Based Wordlists

**Rule-Based attacks** assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre-existing wordlists may be useful when generating passwords that fit a policy — for example, manipulating or 'mangling' a password such as `password`: `p@ssword`, `Pa$$word`, `Passw0rd`, and so on.

{% tabs %}
{% tab title="John" %}
[John the ripper](https://github.com/openwall/john) has a config file that contains rule sets, which is located at `/etc/john/john.conf` or `/opt/john/john.conf` depending on your distro or how john was installed. You can read /etc/john/john.conf and look for List.Rules to see all the available rules:

```bash
# Create wordlist from a rule
john --wordlist=/tmp/single-password-list.txt --rules=best64 --stdout | wc -l
```
{% endtab %}

{% tab title="Hashcat" %}
[Hashcat](https://github.com/hashcat/hashcat) has rule sets located at `/usr/share/hashcat/rules/`. To create your own rules, you may check this [hashcat documentation](https://hashcat.net/wiki/doku.php?id=rule\_based\_attack)

```bash
# Create wordlist from a rule
hashcat -r /usr/share/rules/best64.rule wordlist.txt --stdout > new_wordlist.txt

# Crack hash with combinor
# each word of a dictionary is appended to each word in another dictionary. (left and right)
hashcat -m 0 -a 1 hash.txt dict1.txt dict2.txt

# Crack hash with combinor and rule
# -j Single rule applied to each word on the left dictionary
# -k Single rule applied to each word on the right dictionary
hashcat -m 0 -a 1 hash.txt dict1.txt dict1.txt -j '$-' -k '$!'
```
{% endtab %}

{% tab title="Psudohash" %}
[Pseudohash](https://github.com/t3l3machus/psudohash) is a Python password list generator tool that can generates millions of keyword-based password mutations in seconds.

```bash
# --common-paddings-after  Append common paddings after each mutated word
# --common-paddings-before Append common paddings before each mutated word
# --custom-paddings-only Use only user provided paddings for word mutations (must be used with -ap AND (-cpb OR -cpa))
# --append-padding VALUES Add comma seperated values to common paddings
# --append-numbering LEVEL Append numbering range at the end of each word mutation (before appending year or common paddings).

#Examples
python3 psudohash.py -w password --common-paddings-after -y 2020-2023
python3 psudohash.py -w password --common-paddings-before -an 3 -y 1990-2022
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://tryhackme.com/room/passwordattacks" %}

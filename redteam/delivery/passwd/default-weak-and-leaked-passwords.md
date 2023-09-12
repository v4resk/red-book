# Default, weak & Leaked Passwords

## Theory

In the realm of cybersecurity, default, weak, and leaked passwords are the Achilles' heel of digital defenses. For red teamers, understanding these vulnerabilities is key to breaking through security barriers. On this page, we're taking a look at default, weak, and leaked passwords.

## Practice

### Default Passwords

Before performing password attacks, it is worth trying a couple of default passwords against the targeted service. Manufacturers set default passwords with products and equipment such as switches, firewalls, routers. There are scenarios where customers don't change the default password, which makes the system vulnerable. Here are some websites that provides default passwords for various products :

* [Cirt.net](https://cirt.net/passwords)
* [Default-password](https://default-password.info/)
* [Datarecovery](https://datarecovery.com/rd/default-passwords/)

### Leaked Passwords

Sensitive data such as passwords or hashes may be publicly disclosed or sold as a result of a breach. These public or privately available leaks are often referred to as 'dumps'. Depending on the contents of the dump, an attacker may need to extract the passwords out of the data. In some cases, the dump may only contain hashes of the passwords and require cracking in order to gain the plain-text passwords. Here are some websites and tools that provides resources about leaked passwords :

* [SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)
* [HaveIBeenPwned](https://haveibeenpwned.com/)
* [BreachDirectory](https://breachdirectory.org/)
* &#x20;[Breachforums.is](https://breachforums.is)

{% tabs %}
{% tab title="BreachCheck" %}
[BreachCheck](https://github.com/v4resk/BreachCheck) is a Python tool that use the [BreachDirectory API](https://rapidapi.com/rohan-patra/api/breachdirectory/) for finding passwords in known data breaches and leaks of compromised email addresses or usernames.

```bash
#Simple use, target can be username or email
python BreachCheck.py -t <target>

#Output passwords to a file
python BreachCheck.py -t <target> -oN target_passwords.txt
```
{% endtab %}

{% tab title="PwnedOrNot" %}
[PwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) is an other python tool for finding passwords of compromised email addresses. It use the [HaveIBeenPwned v3 API](https://haveibeenpwned.com/API/v3).

```bash
# Check Single Email
python3 pwnedornot.py -e <email>
```
{% endtab %}
{% endtabs %}

### Weak Passwords

Professionals collect and generate weak password lists over time and often combine them into one large wordlist. Lists are generated based on their experience and what they see in pentesting engagements. These lists may also contain leaked passwords that have been published publically. Here are some of the common weak passwords lists :&#x20;

* [https://wiki.skullsecurity.org/index.php?title=Passwords](https://wiki.skullsecurity.org/index.php?title=Passwords) - This includes the most well-known collections of passwords.
* [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - A huge collection of all kinds of lists, not only for password cracking.

## Resources

{% embed url="https://tryhackme.com/room/passwordattacks" %}

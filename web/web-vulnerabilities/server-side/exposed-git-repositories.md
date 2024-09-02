---
description: OWASP A3:2017-Sensitive Data Exposure
---

# Exposed Git Repositories

## Theory

The exposure of Git repositories on a webserver often occurs due to misconfigurations, where the `.git` directory is left accessible without proper access controls.&#x20;

If we encounter an application with an exposed .`git` directory, we can retrieve the entire repository. This enables us to extract valuable information, such as the remote repository address, commit history, logs, and various metadata. Accessing these details may reveal sensitive data, including proprietary code, hard-coded API keys, and credentials, which can then be leveraged to escalate our attack and further compromise the application's security.

## Practice

### Enumeration

{% tabs %}
{% tab title="httpx" %}
We may use [httpx](https://github.com/projectdiscovery/httpx) to check if the `.git/HEAD` file contains `refs/heads` for a list of domains.\
This one-liner will only match if directory listing is enabled.

```bash
cat domains.txt | httpx -path /.git/HEAD -silent -mr "refs/heads"
```
{% endtab %}

{% tab title="Feroxbuster" %}
When performing web directory fuzzing on a target with [Feroxbuster](https://github.com/epi052/feroxbuster) or any other tool, using the [common.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt) wordlist from [SecLists](https://github.com/danielmiessler/SecLists) can help uncover any exposed `.git` directories.

```bash
feroxbuster -u http://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```
{% endtab %}

{% tab title="Google Dorks" %}
We can use the Google search engine to search for exposed `.git` repository with the following [Google Dorks](exposed-git-repositories.md#google-dorks)

```bash
intext:"index of" ".git"
{intitle: indexof/.git }
intitle:"index of" "/.git/config"
filetype:git -github.com inurl:"/.git"
```
{% endtab %}

{% tab title="Gitfinder" %}
This python script from [GitTools](https://github.com/internetwache/GitTools) identifies websites with publicly accessible `.git` repositories from a list of domains. It checks if the `.git/HEAD` file contains `refs/heads`.

```
./gitfinder.py -i domains.txt
```
{% endtab %}
{% endtabs %}

### Dump&#x20;

{% tabs %}
{% tab title="GitTools" %}
**gitdumper** from [GitTools](https://github.com/internetwache/GitTools) can be used to download as much as possible from the found .git repository from webservers which do not have directory listing enabled.

```
./gitdumper.sh http://target.com/.git/ dest-dir
```

**extractor.sh** from [GitTools](https://github.com/internetwache/GitTools) can then be used in combination with **gitdumper** in case the downloaded repository is incomplete. This tool extract commits and their content from a broken repository.

```
./extractor.sh /tmp/mygitrepo /tmp/mygitrepodump
```
{% endtab %}

{% tab title="goop" %}
[goop](https://github.com/nyancrimew/goop) (Golang) is tool to dump a git repository from a website.

```bash
goop target.com
```
{% endtab %}

{% tab title="git-dumper" %}
[git-dumper](https://github.com/arthaud/git-dumper) (python) is a tool to dump a git repository from a website.

```bash
git-dumper http://target.com/.git ~/TargetOutputFolder
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure" %}

{% embed url="https://medium.com/stolabs/git-exposed-how-to-identify-and-exploit-62df3c165c37" %}

{% embed url="https://infosecwriteups.com/exposed-git-directory-exploitation-3e30481e8d75" %}

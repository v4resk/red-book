# Open-Source Code

Theory

Online repositories of code hold a window into an organization's technology stack, revealing the programming languages and frameworks they employ. In some rare instances, developers have unintentionally exposed sensitive information, including critical data and credentials, within public repositories. These inadvertent revelations may present a unique opportunity us.

## Practice

To automate the process of searching sensitives files and hardcoded credentials in **Git repositories**, we may use following tools

{% tabs %}
{% tab title="Github Dorks" %}
[Github-dorks](https://github.com/techgaun/github-dorks) is a python tools used to search leaked secrets via github search. Its collection of Github dorks can reveal sensitive personal and/or organizational information such as private keys, credentials, authentication tokens, etc.&#x20;

```bash
# search a single repo
github-dork.py -r techgaun/github-dorks

# search all repos of a user
github-dork.py -u techgaun  

# search all repos of an organization
github-dork.py -u dev-nepal
```

Alternatively, we can manualy search for specific dorks, without using [Github-dorks](https://github.com/techgaun/github-dorks) :&#x20;

<figure><img src="../../.gitbook/assets/Capture d’écran_2024-08-22_00-29-55 (1).png" alt=""><figcaption></figcaption></figure>

Examples of Github Dorks are :

| Dork                                           | Description                                          |
| ---------------------------------------------- | ---------------------------------------------------- |
| filename:.npmrc \_auth                         | npm registry authentication data                     |
| filename:.dockercfg auth                       | docker registry authentication data                  |
| extension:pem private                          | private keys                                         |
| extension:ppk private                          | puttygen private keys                                |
| filename:id\_rsa or filename:id\_dsa           | private ssh keys                                     |
| filename:wp-config.php                         | wordpress config files                               |
| filename:.env MAIL\_HOST=smtp.gmail.com gmail  | smtp configuration (try different smtp services too) |
| shodan\_api\_key language:python               | Shodan API keys (try other languages too)            |
| /"sk-\[a-zA-Z0-9]{20,50}"/ language:Shell      | Open AI API Keys                                     |
| "api\_hash" "api\_id"                          | Telegram API token                                   |
{% endtab %}

{% tab title="Noseyparker" %}
[Noseyparker](https://github.com/praetorian-inc/noseyparker) is a command-line program that finds secrets and sensitive information in textual data and Git history.

```bash
# Scan a repo
noseyparker scan --datastore np.myDataStore --git-url <repo-url>

# Scan all repo of an user
noseyparker scan --datastore np.myDataStore --github-user <username>

# Scan all repo of an organization
noseyparker scan --datastore np.myDataStore --github-organization <NAME>

# Show result of a scan
noseyparker report -d np.myDataStore
```
{% endtab %}

{% tab title="GitHunt" %}
[GitHunt](https://github.com/v4resk/GitHunt) is a (Python) tool for detecting sensitive data exposure in GitHub repositories, leveraging GitHub's search functionality.

```bash
# See available hunting modules
python GitHunt.py hunt -h

# Hunt for OpenAI API Keys
python GitHunt.py hunt -m OpenAI

# Export all valid OpenAI API keys found in a json 
python GitHunt.py db -m OpenAI -f json -o ~/export.json
```
{% endtab %}

{% tab title="Gitleaks" %}
[Gitleaks](https://github.com/gitleaks/gitleaks) (Go) is a SAST tool for **detecting** and **preventing** hardcoded secrets like passwords, api keys, and tokens in git repos.

```bash
./gitleaks detect -v -r=<GIT_REPO_URL>
```
{% endtab %}

{% tab title="Gitrob" %}
[Gitrob](https://github.com/michenriksen/gitrob) (Go) is a tool to help find potentially sensitive files pushed to public repositories on Github. It will clone repositories belonging to a user or organization down to a configurable depth and iterate through the commit history and flag files that match signatures for potentially sensitive files.

{% hint style="info" %}
Gitrob will need a Github access token in order to interact with the Github API. See [Create a personal access token](https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/).
{% endhint %}

```bash
# Run it !
# With <TARGET> an organization/user profile (i.e v4resk)
gitrob -github-access-token <TOKEN> <TARGET> 
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://github.com/techgaun/github-dorks" %}

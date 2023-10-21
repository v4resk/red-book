# Open-Source Code

## Theory

Online repositories of code hold a window into an organization's technology stack, revealing the programming languages and frameworks they employ. In some rare instances, developers have unintentionally exposed sensitive information, including critical data and credentials, within public repositories. These inadvertent revelations may present a unique opportunity us.

## Practice

To automate the process of searching sensitives files and hardcoded credentials in **Git repositories**, we may use following tools

{% tabs %}
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

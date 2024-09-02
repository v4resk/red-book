# Google Dorks

## Theory

Google dorking is a technique of using the Google search engine to search for vulnerabilities or to retrieve sensitive data. This technique relies on the results of the exploration and indexation of websites by the Googlebot. We can perform advanced search queries using various operators that allow us to reach our goal.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

## Practice

Here are some operators that might be useful

```bash
# Specify the filetype "pdf" and search the term "email address".
filetype:pdf "email address"

# Search all URLs containing the word "edu" and search the term "login" in the urls.
inurl:edu "login"

# Searches keywords contained in the page title.
intitle:pentesting

# Search the term "DB_USER" contained in the given site "github.com".
site:github.com "DB_USER"
site:github.com "DB_PASSWORD"

# Views cached content
cache:example.com
```

### Google Hacking Database (GHDB)

[The Google Hacking Database(GHDB)](https://www.exploit-db.com/google-hacking-database) is a database of search queries (dorks) used to find sensitive publicly available information or vulnerabilities. This is hosted by [exploit-db](https://www.exploit-db.com/)

### Useful dorks

{% tabs %}
{% tab title="Subdomains" %}
You can use this google dorks to enum subdomains of a website

```bash
#Search for subdomains 
site:*.domain.com

#Search for subdomains with 'admin' in title
site:*.domain.com intitle:admin
```
{% endtab %}

{% tab title="Directory Listing" %}
You can use this google dorks to enum websites with directory listing enabled

```bash
intitle:"Directory Listing For"
intitle:"index of"
```
{% endtab %}
{% endtabs %}

## Ressource

{% embed url="https://www.exploit-db.com/google-hacking-database" %}

{% embed url="https://exploit-notes.hdks.org/exploit/reconnaissance/google-dorks/" %}

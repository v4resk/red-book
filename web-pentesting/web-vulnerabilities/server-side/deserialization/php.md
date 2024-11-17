# PHP Deserialization

## Theory

PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. Since PHP allows object serialization, attackers could pass ad-hoc serialized strings to a vulnerable **`unserialize()`** call, resulting in an arbitrary PHP object(s) injection into the application scope.

## Practice

{% tabs %}
{% tab title="Enumerate" %}
If the PHP application use the `unserialize()` function whose parameter is not correctly satanized, then it is vulnerable.

```php
<?php
$cookie = base64_decode($_COOKIE['PHPSESSID']);
unserialize($cookie);
?>
```
{% endtab %}

{% tab title="Payloads" %}
PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a `User` object with the attributes:

```
$user->name = "carlos";
$user->isAdmin = true;
```

When serialized, this object may look something like this:

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:7:"isAdmin":b:1;}
```

* `O:4:"User"` - An object with the 4-character class name `"User"`
* `2` - the object has 2 attributes
* `s:4:"name"` - The key of the first attribute is the 4-character string `"name"`
* `s:6:"carlos"` - The value of the first attribute is the 6-character string `"carlos"`
* `s:7:"isAdmin"` - The key of the second attribute is the 7-character string `"isAdmin"`
* `b:1` - The value of the second attribute is the boolean value `true`
{% endtab %}

{% tab title="Tools" %}
[**PHPGGC(**PHP Generic Gadget Chains)](https://github.com/ambionics/phpggc) is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.

```bash
phpggc -l
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md" %}

{% embed url="https://portswigger.net/web-security/deserialization/exploiting" %}

{% embed url="https://www.phpinternalsbook.com/php5/classes_objects/serialization.html" %}
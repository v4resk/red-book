# Enum Databases

## Theory

When exploiting SQL injection vulnerabilities, or when you gain access to the database itself, it is often necessary to gather some information about the database itself. This includes the type and version of the database software, and the contents of the database in terms of which tables and columns it contains or even users and permissions informations.

## Practice

{% hint style="info" %}
Some queries on this page can be used with different [SQLi techniques](../../web-vulnerabilities/server-side/sql-injection/) as UNION or Blind based attacks
{% endhint %}

### Database version

Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software.\
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
#Or
SELECT DB_NAME(N); — for N = 0, 1, 2, …

#Or in mssqlclient's impacket shell
enum_db
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
We can extract current database structure with the following query:

```sql
SELECT sql FROM sqlite_schema;
```

We can list all databases with the following query:

```sql
PRAGMA database_list;
SELECT name FROM pragma_database_list;
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
SELECT name FROM master..sysobjects WHERE xtype = ‘U’; — use xtype = ‘V’ for views
SELECT name FROM someotherdb..sysobjects WHERE xtype = ‘U’;
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name=’sometable’; — list colum names and types for master..sometable

SELECT table_name FROM information_schema.tables;
SELECT table_name FROM information_schema.tables WHERE table_catalog = DB_NAME();
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
SELECT table_name FROM all_tables;

SELECT table_name FROM all_tables WHERE owner = USER;
SELECT table_name FROM all_tables WHERE owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA');

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

### DB Users

Additionally, we may enumerate DB users with following queries.

{% tabs %}
{% tab title="MySQL" %}
```sql
#Get all users
SELECT * FROM mysql.user;

#Get current user
SELECT user();
```
{% endtab %}

{% tab title="MSSQL" %}
In MSSQL, [**logins** ](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-login?view=sql-server-ver16)and [**users** ](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user?view=sql-server-ver16)are both types of [_security principals_](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine?view=sql-server-ver16), but they operate at different scopes. &#x20;

* A **login** is defined at the **server level** and is used to authenticate access to the SQL Server instance
* An **user** is defined at the **database level** and controls access to specific database resources.&#x20;

A single login can be associated with **one user per database**, allowing it to access multiple databases under distinct user contexts.

#### Enumerate Users

```sql
#Get all users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;

#Get current user
select user_name();

#Or in mssqlclient's impacket shell
enum_users
```

#### Enumerate Logins

```sql
# Get all logins
SELECT r.name, r.type_desc, r.is_disabled, sl.sysadmin, sl.securityadmin, sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin FROM master.sys.server_principals r LEFT JOIN master.sys.syslogins sl ON sl.sid = r.sid WHERE r.type IN ('S','E','X','U','G');

#Or in mssqlclient's impacket shell
enum_logins
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
#Get all users in the Oracle Databas
SELECT * FROM dba_users;
#Get all users that are visible to the current user
SELECT * FROM all_users;

#Get current user
SELECT * FROM user_users;
```
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
#Get all users
SELECT * FROM pg_catalog.pg_user;
#Or
SELECT usename AS role_name,
 CASE
  WHEN usesuper AND usecreatedb THEN
    CAST('superuser, create database' AS pg_catalog.text)
  WHEN usesuper THEN
    CAST('superuser' AS pg_catalog.text)
  WHEN usecreatedb THEN
    CAST('create database' AS pg_catalog.text)
  ELSE
    CAST('' AS pg_catalog.text)
 END role_attributes
FROM pg_catalog.pg_user
ORDER BY role_name desc;
#Or if in a SQL Shell
postgres> \du+

#Get current user
SELECT current_user;
```
{% endtab %}
{% endtabs %}





### Permissions & Privileges

Sometimes it can be useful to enumerate user's permissions or privileges. We can acheive this with the following queries.&#x20;

{% tabs %}
{% tab title="MySQL" %}
```sql
#Show privileges granted to the current MySQL user
mysql> SHOW GRANTS;

#Show privileges granted to a particular MySQL user account from a given host
mysql> SHOW GRANTS FOR 'user_name'@'host';
mysql> SHOW GRANTS FOR 'root'@'localhost';
```
{% endtab %}

{% tab title="MSSQL" %}
Introduction about some MSSQL terms:

1. **Securable:** These are the resources to which the SQL Server Database Engine authorization system controls access. There are three broader categories under which a securable can be differentiated:
   * Server – For example databases, logins, endpoints, availability groups and server roles
   * Database – For example database role, application roles, schema, certificate, full text catalog, user
   * Schema – For example table, view, procedure, function, synonym
2. **Permission:** Every SQL Server securable has associated permissions like ALTER, CONTROL, CREATE that can be granted to a principal. Permissions are managed at the server level using logins and at the database level using users.
3. **Principal:** The entity that receives permission to a securable is called a principal. The most common principals are logins and database users. Access to a securable is controlled by granting or denying permissions or by adding logins and users to roles which have access.

```sql
# Show all different securables names
SELECT distinct class_desc FROM sys.fn_builtin_permissions(DEFAULT);

# Show all possible permissions in MSSQL
SELECT * FROM sys.fn_builtin_permissions(DEFAULT);

# Get all my permissions over securable type SERVER
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

# Get all my permissions over a database
USE <database>
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');

# Get members of the role "sysadmin"
Use master
EXEC sp_helpsrvrolemember 'sysadmin';

# Get if the current user is sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

# Get users that can run xp_cmdshell (except DBA)
Use master
EXEC sp_helprotect 'xp_cmdshell'

# Make user DB Admin (DBA)
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```
{% endtab %}

{% tab title="OracleSQL" %}
```sql
# Get all system privileges granted to all users 
# GRANTEE is the name, role, or user that was assigned the privilege.
# PRIVILEGE is the privilege that is assigned.
# ADMIN_OPTION indicates if the granted privilege also includes the ADMIN option.
SELECT * FROM DBA_SYS_PRIVS;

# Get which users have direct grant access to a table
# GRANTEE is the name, role, or user that was assigned the privilege.
# TABLE_NAME is the name of the object (table, index, sequence, etc).
# PRIVILEGE is the privilege assigned to the GRANTEE for the associated object.
SELECT * FROM DBA_TAB_PRIVS;

#Get current user's privilegs
SELECT * FROM USER_SYS_PRIVS;
```

Privileges that are inhereted through other roles will not be readily shown. To resolve this, it is advisable to use this advanced script by David Arthur:&#x20;

{% file src="../../../.gitbook/assets/find_all_privs2.sql" %}
{% endtab %}

{% tab title="PostgreSQL" %}
```sql
#Enumerate users privileges over databases (in a SQL Shell)
postgres> \l

#Enumerate users privileges over tables
SELECT * FROM information_schema.table_privileges;
#in a SQL Shell
postgres> \du+

#Enumerate specific user privileges
SELECT * from information_schema.table_privileges WHERE grantee = 'username';

#Enumerate users privileges over a specific table
SELECT * from information_schema.table_privileges WHERE table_name = 'MyTableName';
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://portswigger.net/web-security/sql-injection" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" %}

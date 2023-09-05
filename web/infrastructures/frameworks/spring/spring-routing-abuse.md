# Spring Routing Abuse

## **Theory**

Routing misconfigurations in the Spring Framework can pose significant security risks, potentially leading to protected URL bypass, path traversal, or information leaks.&#x20;

## **Practice**

### Exposing routes

Exposing the relevant interfaces and parameter information of a Spring application is not a vulnerability, but it can help to understand an application. Moreover, it can be used while checking for access control vulnerabilities, etc.

{% tabs %}
{% tab title="swagger" %}
Check the following routes to see if an application provides path and parameter information:

```
/v2/api-docs
/swagger-ui.html
/swagger
/api-docs
/api.html
/swagger-ui
/swagger/codes
/api/index.html
/api/v2/api-docs
/v2/swagger.json
/swagger-ui/html
/distv2/index.html
/swagger/index.html
/sw/swagger-ui.html
/api/swagger-ui.html
/static/swagger.json
/user/swagger-ui.html
/swagger-ui/index.html
/swagger-dubbo/api-docs
/template/swagger-ui.html
/swagger/static/index.html
/dubbo-provider/distv2/index.html
/spring-security-rest/api/swagger-ui.html
/spring-security-oauth-resource/swagger-ui.html
```
{% endtab %}

{% tab title="actuators" %}
We may use the [spring-boot.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt) wordlist from SecList to fuzz actuators URLs

```bash
feroxbuster -u http://<TARGET>/ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="Exploit" %}
Spring Framework **versions prior to 5.3** have a setting called `useSuffixPatternMatch`. It enable suffix pattern matching and it's set to true by default.

When enabled, methods mapped to `/restrictedURL` would also match `/restrictedURL[.].*`. So this configuration has a potential to bypass URL filters and allow access to restricted areas.

```bash
#Without bypass
$ curl http://<TARGET>/adminURL
403 Forbidden

#With bypass
$ curl http://<TARGET>/adminURL.V4RESK
200 OK
```
{% endtab %}
{% endtabs %}

### Path traversal

{% tabs %}
{% tab title="Exploit" %}
Spring Boot > 2.2.6 treats `https://website.com/allowed/..;/internal` same as `https://website.com/allowed/../internal`.

This can lead to inconsistency between Spring and middleware. For instance, if an application is deployed behind nginx, you can bypass restrictions on allowed paths. Assume nginx forward all request to `/allowed/` to an application and deny other requests. In this case, a request to `/allowed/../internal` will be blocked, however, `/allowed/..;/internal` is not - nginx will pass it as is to an application and it will hit `/internal`.

```bash
$ curl http://<TARGET>/allower/..;/internal
```
{% endtab %}
{% endtabs %}

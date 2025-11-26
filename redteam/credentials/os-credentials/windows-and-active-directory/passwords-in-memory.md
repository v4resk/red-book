# In-memory secrets

## Theory

Just like the LSASS process on Windows systems allowing for [LSASS dumping](/broken/pages/wAjDzPwV8LLtm6RWJbLf), some programs sometimes handle credentials in the memory allocated to their processes, sometimes allowing attackers to dump them.

## Practice

{% hint style="info" %}
Just like [LSASS dumping](/broken/pages/wAjDzPwV8LLtm6RWJbLf), this technique needs the attacker to have admin access on the target machine since it involves dumping and handling volatile memory.
{% endhint %}

{% tabs %}
{% tab title="Windows" %}
On Windows systems, tools like [LaZagne](https://github.com/AlessandroZ/LaZagne) (Python) and [mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used to extract passwords from memory but they focus on [LSASS dumping](/broken/pages/wAjDzPwV8LLtm6RWJbLf).

```powershell
LaZagne.exe all
```
{% endtab %}
{% endtabs %}

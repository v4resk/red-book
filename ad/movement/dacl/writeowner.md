# WriteOwner

The `WriteOwner` permission allows a user to change the ownership of an object to a different user or principal, including one controlled by an attacker. By exploiting this permission, an attacker can take ownership of a target object.

Once the attacker successfully changes the ownership of the object to a principal under their control, they gain the ability to fully manipulate the object. This includes modifying permissions to grant themselves or others full control over the object. For example, the attacker could grant “Full Control” permissions, allowing unrestricted access to read, write, or delete the object.

* WriteOwner permissions on a **group** allow granting the right to add members to that group.
* WriteOwner permissions on a **user** allow granting full control over the user object.
* WriteOwner permissions on a **computer** object allow granting full control over the computer object.
* WriteOwner permissions on a **domain** object allow granting the ability to perform a DCSync operation.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, we can change the owner of an object using [owneredit.py ](https://github.com/fortra/impacket/blob/master/examples/owneredit.py)(Python)

```bash
owneredit.py -new-owner $ControlledUser -target $TargetRessource -action write $DOMAIN/$ControlledUser:$Password -dc-ip $DC_IP
```

The owner can now take full control of the object he owns using [dacledit.py](https://github.com/fortra/impacket/blob/master/examples/dacledit.py) (Python)

```bash
dacledit.py -rights FullControl -principal $ControlledUser -target $TargetRessource -action write $DOMAIN/$ControlledUser:$Password -dc-ip $DC_IP
```
{% endtab %}

{% tab title="Windows" %}

{% endtab %}
{% endtabs %}

### Resources

{% embed url="https://www.hackingarticles.in/abusing-ad-dacl-writeowner/" %}

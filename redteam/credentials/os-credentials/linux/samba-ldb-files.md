# Samba LDB files

## Theory

A [Samba](https://wiki.samba.org/index.php/Samba_Security_Documentation) AD DC is Samba running the **Active Directory Domain Controller** role on Linux. In that mode, Samba is not just a file server: it also provides core AD services, including LDAP-backed directory services, a Kerberos KDC, and AD replication logic (DRSUAPI).

#### LDB - Samba's Embedded Database Layer

Internally, Samba stores AD data using [**LDB**](https://wiki.samba.org/index.php/LDB), an embedded LDAP-like database library. LDB is not fully LDAP-compliant by design, it is modular and uses compliance modules where needed. Under the hood, LDB stores its data in [**TDB**](https://tdb.samba.org/) (Trivial Database) files, giving it ACID-style transactional properties. This is why LDB files have a `.ldb` extension but internally behave as TDB-backed stores.

All security-sensitive LDB files live in Samba's **`private/`** directory, which is readable only by root. The default location varies by installation method:

| Installation           | Path                        |
| ---------------------- | --------------------------- |
| Debian/Ubuntu packages | `/var/lib/samba/private/`   |
| RHEL/CentOS packages   | `/var/lib/samba/private/`   |
| Compiled from source   | `/usr/local/samba/private/` |

#### Key Files

**`sam.ldb`** is the main AD directory database for the DC role. It holds all domain objects — users, groups, computers, GPOs — along with their AD attributes. Two attributes are of direct interest for credential extraction:

* **`unicodePwd`**: the user's NT hash, stored as raw binary (16 bytes). Samba's LDB layer represents it base64-encoded with double-colon notation (`::`) in query output. The NT hash is an unsalted MD4 digest of the password encoded as UTF-16LE — identical in format to a Windows DC's NT hash and usable for Pass-the-Hash or offline cracking. This attribute is **not readable via the LDAP protocol** — it can only be accessed through direct file I/O on the DC.
* **`supplementalCredentials`**: a binary blob containing all long-term Kerberos encryption keys for the account (AES-256, AES-128, and — unless explicitly disabled — RC4/arcfour-hmac-md5). The RC4 Kerberos key is mathematically identical to the NT hash. These keys can be used to forge Kerberos tickets (Golden/Silver Ticket attacks).

{% hint style="warning" %}
Since Samba 4.17, the `nt hash store` option in `smb.conf` controls whether the NT hash is stored at all. When set to `never`, `unicodePwd` will be absent or zeroed for users who changed their password after that setting was applied, and only AES Kerberos keys remain. This is worth checking before assuming you can extract NT hashes.
{% endhint %}

**`secrets.ldb`** is a separate, schema-less local secret store used internally by Samba components. Unlike `sam.ldb`, it stores no schema (arbitrary data can be inserted), and it holds sensitive DC-side material: the machine account password, domain SID, trust account secrets, and DRSUAPI-related credentials. It is not the user password database.

**Other notable files in `private/`:**

* `secrets.keytab` — Kerberos keytab for DC service principals (LDAP, CIFS, HOST…)
* `dns.keytab` — Kerberos keytab for the DNS service principal
* `krb5.conf` — Kerberos realm configuration generated at provisioning time

## Practice

All methods below require **root access on the Samba AD DC**, since the `private/` directory is mode `700` and all files within it are mode `600`.

{% tabs %}
{% tab title="ldbsearch" %}
[`ldbsearch`](https://linux.die.net/man/1/ldbsearch) queries an LDB database directly on disk. This is the most reliable bulk extraction method.

```bash
# Dump sAMAccountName + unicodePwd for all user objects
ldbsearch -H /var/lib/samba/private/sam.ldb \
  '(objectClass=user)' \
  sAMAccountName unicodePwd
```

The `unicodePwd` value is returned base64-encoded. To convert it to the standard 32-character hex NT hash:

```bash
# Decode a single unicodePwd value to hex NT hash
echo -n "<base64_value>" | base64 -d | xxd -p | tr -d '\n'
```

{% hint style="warning" %}
If `LDB_MODULES_PATH` is not set in your environment, `ldbsearch` may return empty results or fail to load modules. Set it first:

```bash
export LDB_MODULES_PATH=/usr/lib/x86_64-linux-gnu/samba/ldb
# path varies by distro — use: find / -name "*.so" -path "*/samba/ldb*" 2>/dev/null
```
{% endhint %}
{% endtab %}

{% tab title="samba-tool" %}
[`samba-tool`](https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html) has a `user getpassword` subcommand that can retrieve credential attributes for one user at a time, or filtered by an LDAP expression. This must be run **locally on the DC** as root.

```bash
# Single user
samba-tool user getpassword <username> --attributes=sAMAccountName,unicodePwd

# All enabled domain users (bulk)
samba-tool user getpassword \
  --filter='(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' \
  --attributes=sAMAccountName,unicodePwd
```

The `unicodePwd` value is returned base64-encoded, identical to `ldbsearch` output. Apply the same hex conversion to get the standard NT hash format.

{% hint style="info" %}
`samba-tool user getpassword` can also retrieve `supplementalCredentials` (Kerberos keys) and, if GPG key IDs are configured in `smb.conf`, it can expose cleartext passwords via `--decrypt-samba-gpg`
{% endhint %}
{% endtab %}

{% tab title="pdbedit (tdbsam only)" %}
`pdbedit -Lw` is the classic Samba credential dumping command, but it only works when Samba is using the **`tdbsam`** passdb backend (old NT4-style Samba, or Samba in standalone/member mode):

```bash
pdbedit -Lw
```

Output format: `username:RID:LM_HASH:NT_HASH:::`

{% hint style="danger" %}
`pdbedit` does **not** read `sam.ldb` and will **not** work against a Samba AD DC configured as `server role = active directory domain controller`. It reads `passdb.tdb`, which does not exist on a Samba AD DC. Using it on an AD DC will return an empty result or an error.
{% endhint %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://infosecwriteups.com/samba-active-directory-domain-controller-linux-what-to-do-when-impacket-bloodhound-dont-work-1faee4828d5b" %}

---
description: MITRE ATT&CK™ Brute Force - Technique T1110
---

# Brute-Force

A brute-force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly. We may use brute-force techniques to gain access to accounts when passwords are unknown (online) or when password hashes are obtained (offline).

Although this section is entitled "Brute-Force", there are various types of password attack, which we will be concentrating on:

* **Brute-force attacks**: every possibility for a given character set and a given length (i.e. `aaa`, `aab`, `aac`, ...) is sent to the target service or hashed and compared against the target hash.
* **Dictionary attacks**: every word of a given list (a.k.a. dictionary) is sent to the target service or hashed and compared against the target hash.
* **Rainbow table attacks**: use pre-computed lookup tables to crack password hashes. These tables store a mapping between the hash of a password, and the correct password for that hash. The hash values are indexed so that it is possible to quickly search the database for a given hash. Note that this attack cannot work if the hashed value is salted.

{% content-ref url="online-attacking-services.md" %}
[online-attacking-services.md](online-attacking-services.md)
{% endcontent-ref %}

{% content-ref url="offline-password-cracking.md" %}
[offline-password-cracking.md](offline-password-cracking.md)
{% endcontent-ref %}

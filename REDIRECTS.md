# Redirects needed at cutover

`red.infiltr8.io/<path>` -> `infiltr8.io/redbook/<path>` for every page (1:1).

## Paths that ALSO changed, beyond the /redbook prefix

The Kerberos section was regrouped into semantic families (roasting, pass-the,
principal-confusion), matching The Hacker Recipes' current structure.

| old (GitBook)                                   | new                                                          |
| :---------------------------------------------- | :----------------------------------------------------------- |
| /ad/movement/kerberos/kerberoast                | /redbook/ad/movement/kerberos/roasting/kerberoast             |
| /ad/movement/kerberos/asreproast                | /redbook/ad/movement/kerberos/roasting/asreproast             |
| /ad/movement/kerberos/asreqroast                | /redbook/ad/movement/kerberos/roasting/asreqroast             |
| /ad/movement/kerberos/ptt                       | /redbook/ad/movement/kerberos/pass-the/ptt                    |
| /ad/movement/kerberos/ptk                       | /redbook/ad/movement/kerberos/pass-the/ptk                    |
| /ad/movement/kerberos/ptc                       | /redbook/ad/movement/kerberos/pass-the/ptc                    |
| /ad/movement/kerberos/opth                      | /redbook/ad/movement/kerberos/pass-the/opth                   |
| /ad/movement/kerberos/pass-the-certificate      | /redbook/ad/movement/kerberos/pass-the/pass-the-certificate   |
| /ad/movement/kerberos/samaccountname-spoofing   | /redbook/ad/movement/kerberos/principal-confusion/samaccountname-spoofing |

Everything else keeps its path; only the `/redbook` prefix is added.

Also required, on the landing page rather than here: serve `robots.txt` from
`infiltr8.io/robots.txt` pointing at
`https://infiltr8.io/redbook/sitemap.xml`. Crawlers never look under /redbook/.

## Trusts split (Option A)

The trusts page was split into a folder. The main URL is unchanged, so no
redirect is needed for it; only the forged-tickets anchors moved.

| old (GitBook)                                    | new                                                        |
| :----------------------------------------------- | :---------------------------------------------------------- |
| /ad/movement/domain-trusts                       | /redbook/ad/movement/domain-trusts            (unchanged path) |
| /ad/movement/domain-trusts#referral-ticket       | /redbook/ad/movement/domain-trusts/forged-tickets#referral-ticket |
| /ad/movement/domain-trusts#golden-ticket         | /redbook/ad/movement/domain-trusts/forged-tickets#golden-ticket   |

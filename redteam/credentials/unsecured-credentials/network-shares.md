# Network shares

## Theory

In organization networks, it is common to find passwords in random files (logs, config files, personal documents, Office documents, ...). Other credential dumping techniques ([SAM & LSA](/broken/pages/3llRWtbOW9nOdqiXY6Xm), [NTDS.dit](/broken/pages/p0zd2jmjjzPDDfj8h2Jr), some [web browsers](/broken/pages/vHRt2n7o6deFCl4lze1Z), ...) could be considered as sub-techniques of credential dumping from files. This recipe focuses on the techniques that allow to gather password and sensitive information from generic and random files other than the ones involved in the sub-techniques mentioned before.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, the [manspider](https://github.com/blacklanternsecurity/MANSPIDER) (Python) tool can be used to find sensitive information across a number of shares.

```bash
manspider.py --threads 50 $IP_RANGE/$MASK -d $DOMAIN -u $USER -p $PASSWORD --content "set sqlplus" "password ="
```

{% hint style="info" %}
Manually, shares can also be mounted or [exfiltrated](../../exfiltration/smb.md) and grepped for interesting information.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the following commands should help find interesting information across local files and network shares.

```bash
findstr /snip password *.xml *.ini *.txt
findstr /snip password *
```

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (Powershell) module can be used to find interesting files as well.

```bash
Find-InterestingFile -LastAccessTime (Get-Date).AddDays(-7)
Find-InterestingFile -Include "private,confidential"
Find-InterestingFile -Path "\\$SERVER\$Share" -OfficeDocs
```

Last but not least, one of the best tools to find sensitive information across a number of shares and local files is [Snaffler](https://github.com/SnaffCon/Snaffler) (C#).

```bash
snaffler.exe -s -o snaffler.log
```
{% endtab %}
{% endtabs %}

## Resource

{% embed url="https://github.com/SnaffCon/Snaffler" %}

{% embed url="https://github.com/blacklanternsecurity/MANSPIDER" %}

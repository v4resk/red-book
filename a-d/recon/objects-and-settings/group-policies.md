# Group policies

## Theory

In certain scenarios, an attacker can gain control over GPOs. Some ACEs can give that control (see [this BlackHat conf](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf), page 28):

* `WriteProperty` to the `GPC-File-Sys-Path` property of a GPO (specific GUID specified)
* `GenericAll`, `GenericWrite`, `WriteProperty` to any property (no GUID specified)
* `WriteDacl`, `WriteOwner`

## Practice

### PowerView

{% tabs %}
{% tab title="Dump All GPO's DACLs" %}
We can enumerate interesting GPO's domain Object's ACL using `Get-NetGPO` and `Get-ObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1).

```powershell
#Enumerate all GPO ACLs
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} |select-object @{Name='SecurityIdentifierName';Expression={"$($_.SecurityIdentifier.Value|Convert-SidToName)"}},@{Name='SecurityIdentifierSID';Expression={"$($_.SecurityIdentifier.Value)"}},@{Name='ActiveDirectoryRights';Expression={"$($_.ActiveDirectoryRights)"}},ObjectDN|ConvertTo-Json -Compress|Out-File gpos.json
```

Then, on your attacking machine, we can use the following command to format results

```bash
#From UTF-16LE to UTF-8
dos2unix gpo.json

#Parsing json results
cat gpo.json|jq '.[]| "\(.SecurityIdentifierName):\(.SecurityIdentifierSID) | Have: \(.ActiveDirectoryRights) | On: \(.ObjectDN)"'
```

{% hint style="info" %}
You may  resolve computer names linked with a GPO as follow&#x20;

```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
{% endhint %}
{% endtab %}

{% tab title="Interesting GPO's" %}
We can enumerate interesting GPOs and GPO's ACLs using `Get-NetGPO` and `Get-ObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1).

```powershell
#Enumerate GPO's ACLs for an user
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "CONTOSO\YourUser"}

#Policies Applied to a Given Computer
Get-DomainGPO -ComputerIdentity COMPUTER01 -Properties Name, DisplayName

#Enumerate a given GPO
"{7EA15487-7F5B-4CE3-C029-CEBE6FFE6D47}" | Get-DomainGPO

#OUs with a Given Policy Applied
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#gpo-delegation" %}

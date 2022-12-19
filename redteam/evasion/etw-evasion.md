# Evading Logging (ETW)

## Theory

[Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) provides a mechanism to trace and log events that are raised by user-mode applications and kernel-mode drivers. 

### ETW Direct Attacks - Opsec considerations

{% hint style="danger" %}
Directly deleting ETW logs can be an OPSEC (Operational Security) risk. 
{% endhint %}  
Assuming an attacker did destroy all of the logs before they were forwarded to a SIEM by the SOC, or if they were not forwarded, how would this raise an alert? An attacker must first consider environment integrity; if no logs originate from a device, that can present serious suspicion and lead to an investigation. Even if an attacker did control what logs were removed and forwarded, defenders could still track the tampering.

**EventID:**
- **1102:** Logs when the Windows Security audit log was cleared  
- **104:** Logs when the log file was cleared  
- **1100:** Logs when the Windows Event Log service was shut down

## Practice

To find where AMSI is instrumented, we can use [InsecurePowerShell](https://github.com/cobbr/InsecurePowerShell) maintained by [Cobbr](https://github.com/cobbr) which is a GitHub fork of PowerShell with security feature removed, and compare it with an [offical PowerShell GitHub](https://github.com/PowerShell/PowerShell).

### PowerShell Downgrade
The PowerShell downgrade attack is a very low-hanging fruit that allows attackers to modify the current PowerShell version to remove security features.  
Most PowerShell sessions will start with the most recent PowerShell engine, but attackers can manually change the version with a one-liner. By "downgrading" the PowerShell version to 2.0, you bypass security features since they were not implemented until version 5.0.

{% tabs %}
{% tab title="Powershell" %}
We can simply use this command to downgrad powershell. This attacked is used in popular tools such as [Unicorn](https://github.com/trustedsec/unicorn)
```bash
PowerShell -Version 2
```
  
{% hint style="danger" %}
Since this attack is such low-hanging fruit and simple in technique, there are a plethora of ways for the blue team to detect and mitigate this attack.
{% endhint %}
{% endtab %}
{% endtabs %}  

## References

{% embed url="https://tryhackme.com/room/monitoringevasion" %}

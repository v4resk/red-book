# Host Discovery

## Theory

One of the very first steps in network recon is to reduce a set (sometimes huge) of IP ranges to a list of active or interesting hosts. Scanning all the ports of each IP is slow and often pointless. Nmap offers a wide variety of host discovery techniques beyond the standard ICMP echo request.

## Practice

{% tabs %}
{% tab title="Nmap" %}
#### Network Sweep

When performing a network sweep with Nmap using the `-sn` option, the host discovery process consists of more than just sending an ICMP echo request. Nmap also sends a TCP SYN packet to port 443, a TCP ACK packet to port 80, and an ICMP timestamp request to verify whether a host is available.

By default, on an ethernet LAN, nmap will perform an [ARP scan](host-discovery.md#arp-scan).

```bash
# Network sweep for IP Range
nmap -sn 192.168.50.1-200

# Network sweep for IP Range using CIDR
nmap -sn 192.168.50.0/24
```

#### TCP SYN Ping

The `-PS` option sends an empty TCP packet with the SYN flag set. The default destination port is 80. Nmap does not care whether the port is open or closed. Either the RST or SYN/ACK response discussed previously tell Nmap that the host is available and responsive.

```bash
# TCP SYN Ping
nmap -sn -PS 192.168.50.0/24

# TCP SYN Ping with custom ports
nmap -sn -PS22-25,80,113,1050,35000 192.168.50.0/24
```

#### TCP ACK Ping

The TCP ACK ping is quite similar to the SYN ping. The difference, as you could likely guess, is that the TCP ACK flag is set instead of the SYN flag. Such an ACK packet purports to be acknowledging data over an established TCP connection, but no such connection exists. So remote hosts should always respond with a RST packet, disclosing their existence in the process.

```bash
# TCP ACK Ping
nmap -sn -PA 192.168.50.0/24

# TCP ACK Ping with custom ports
nmap -sn -PA22-25,80,113,1050,35000 192.168.50.0/24
```

#### UDP Ping

Another host discovery option is the UDP ping, which sends a UDP packet to the given ports. The port list takes the same format as with the previously discussed `-PS` and `-PA` options. If no ports are specified, the default is 40,125.

For most ports, the packet will be empty, though for a few common ports like 53 and 161, a protocol-specific payload will be sent that is more likely to get a response. The `--data-length` option sends a fixed-length random payload for all ports.

```bash
# TCP ACK Ping
nmap -sn -PU 192.168.50.0/24

# TCP ACK Ping with custom ports and data-length specification
nmap -sn -PU53 --data-length 32 192.168.50.0/24
```

#### ICMP Ping Types

Nmap can send the standard packets sent by the ubiquitous ping program. Nmap sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in return from available hosts.

```bash
# -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
nmap -sn -PE 192.168.50.0/24
```

#### ARP Scan

One of the most common Nmap usage scenarios is to scan an ethernet LAN. On most LANs, Hosts frequently block IP-based ping packets, but they generally cannot block ARP requests or responses. **ARP is the default scan type when scanning ethernet hosts**.

The `--send-ip` option tells Nmap to send IP level packets (rather than raw ethernet) even though it is a local network.

```bash
# ARP Scan (useless as default)
nmap -sn -PR 192.168.50.0/24

# Raw IP ping scan (don't send raw ethernet frames) 
nmap -n -sn --send-ip 192.168.50.0/24
```
{% endtab %}
{% endtabs %}

## Ressources

{% embed url="https://nmap.org/book/host-discovery-techniques.html" %}

# Investigation Report: Network Service Discovery

## Findings

- **Technique:** Network Service Discovery
- **MITRE ATT&CK ID:** T1046
- **Tactic:** Discovery
- **Source IP:** `192.168.1.212`
- **First SYN:** `2024-02-02 14:40:36.410417 UTC`
- **First SYN/ACK:** Packet `26`
- **Targets:** Four internal IP addresses
- **Unique destination ports:** 19
- **RDP open:** `192.168.1.102` and `192.168.1.104`
- **Assessment:** Confirmed network-service discovery behavior; authorization unknown

## Investigation Summary

On `2024-02-02` at `14:40:36.410417 UTC`, host `192.168.1.212` began sending TCP SYN probes to multiple service ports across four internal systems. Wireshark analysis identified 19 unique destination ports and a rapid one-to-many probing pattern. Several unanswered probes were retransmitted.

Packet `26` contained the first SYN/ACK response. The response originated from TCP port `3389` on `192.168.1.104`, confirming that RDP was open. A separate SYN/ACK confirmed RDP on `192.168.1.102`. After successful handshakes, the source immediately sent RST/ACK packets without exchanging application data. This behavior is consistent with service enumeration and maps to MITRE ATT&CK T1046.

## Who, What, When, Where, Why, and How

### Who

The observed scanning host was `192.168.1.212`. The available PCAP does not identify the person or process operating that system.

### What

The host conducted rapid TCP discovery against 19 service ports on four internal systems. Open services were identified through SYN/ACK responses.

### When

The first SYN event occurred at `2024-02-02 14:40:36.410417 UTC`. The overall packet capture lasted approximately 6.834 seconds.

### Where

The scanning activity occurred within the `192.168.1.0/24` private network and targeted:

- `192.168.1.101`
- `192.168.1.102`
- `192.168.1.103`
- `192.168.1.104`

### Why

The packet behavior indicates an objective of discovering accessible services. The PCAP does not establish whether the scan was authorized or malicious.

### How

The source sent TCP SYN packets to selected destination ports. Open ports replied with SYN/ACK. The scanner acknowledged successful responses and immediately reset the connections without sending application data.

## Recommendations

1. Determine whether the source is an authorized scanner.
2. If unauthorized, isolate the host and investigate its owner, processes, and recent activity.
3. Restrict RDP to approved administrative pathways.
4. Review RDP authentication logs and endpoint telemetry for follow-on activity.
5. Segment or filter SMB, NetBIOS, and RPC traffic where unnecessary.
6. Detect rapid SYN activity across multiple ports or systems.
7. Correlate network evidence with DHCP, EDR, firewall, and identity logs.

## Conclusion

The investigation confirmed behavior consistent with Network Service Discovery. The scan revealed open RDP services on `192.168.1.102` and `192.168.1.104`. Additional context is necessary to determine intent and authorization.


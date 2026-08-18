I completed a Wireshark packet-capture investigation focused on MITRE ATT&CK T1046: Network Service Discovery.

The analysis identified a host rapidly testing 19 unique TCP ports across four internal systems. By examining SYN, SYN/ACK, ACK, and RST/ACK packets, I confirmed that RDP was open on two targets and distinguished the discovery activity from unrelated background traffic.

This project strengthened my skills in PCAP analysis, TCP three-way-handshake interpretation, port-scan detection, Wireshark display filters, evidence documentation, and MITRE ATT&CK mapping. One important lesson was that packet behavior can confirm service discovery, but asset and authorization records are still needed to determine whether the scan was approved or malicious.

#Cybersecurity #Wireshark #NetworkSecurity #MITREATTACK #SOCAnalyst #ThreatDetection #BlueTeam #PCAPAnalysis

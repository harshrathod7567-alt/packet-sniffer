# Packet Sniffer

A beginner Python project that captures live network traffic using `scapy`, 
extracts protocol/IP/port details, and summarizes the results — a foundational 
skill for network monitoring and intrusion detection.

## ⚠️ Legal & permissions note
- Packet sniffing requires elevated privileges (raw socket access)
- **Linux/Mac:** run with `sudo python3 packet_sniffer.py`
- **Windows:** install [Npcap](https://npcap.com/) first, then run terminal as Administrator
- Only sniff traffic on networks/devices you own or have explicit permission to monitor

## What it does
- Captures a set number of live network packets
- Identifies protocol (TCP/UDP/other), source/destination IPs, and ports
- Summarizes results: protocol breakdown, top destination IPs, top destination ports
- Saves findings to a report file

## Files
- `packet_sniffer.py` — the main script

## Setup
1. Install dependencies: `pip install scapy`
2. (Windows only) Install [Npcap](https://npcap.com/) in WinPcap-compatible mode

## How to run it
1. Run: `sudo python3 packet_sniffer.py` (Linux/Mac) or as Administrator (Windows)
2. Generate some traffic (browse a website) while it captures
3. Check the terminal output and `sniffer_report.txt` for the summary

## Example output
=== Packet Sniffer Report ===

Total packets captured: 30

Protocol breakdown:
TCP: 22
UDP: 8

Top destination IPs:
142.250.72.14: 12 packets
8.8.8.8: 6 packets

Top destination ports:
Port 443: 18 packets
Port 53: 8 packets

## What I learned
- How to capture and parse live network traffic in Python
- The difference between TCP and UDP traffic
- Recognizing common ports (443 = HTTPS, 53 = DNS) and what they indicate
- Using `Counter` for quick data aggregation

## Next steps
- Filter by specific protocol, IP, or port (like a mini Wireshark filter)
- Flag unusual traffic (e.g., unexpected ports, unfamiliar destination IPs)
- Add packet payload inspection for deeper analysis

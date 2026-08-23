from scapy.all import sniff, IP, TCP, UDP
from collections import Counter

captured_packets = []

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            proto = "OTHER"
            src_port = None
            dst_port = None
        
        info = {
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port
        }
        captured_packets.append(info)
        print(f"[{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def write_report(packets, output_file="sniffer_report.txt"):
    proto_counts = Counter(p["proto"] for p in packets)
    dst_ip_counts = Counter(p["dst_ip"] for p in packets)
    dst_port_counts = Counter(p["dst_port"] for p in packets if p["dst_port"])
    
    with open(output_file, 'w') as f:
        f.write("=== Packet Sniffer Report ===\n\n")
        f.write(f"Total packets captured: {len(packets)}\n\n")
        
        f.write("Protocol breakdown:\n")
        for proto, count in proto_counts.items():
            f.write(f"  {proto}: {count}\n")
        
        f.write("\nTop destination IPs:\n")
        for ip, count in dst_ip_counts.most_common(5):
            f.write(f"  {ip}: {count} packets\n")
        
        f.write("\nTop destination ports:\n")
        for port, count in dst_port_counts.most_common(5):
            f.write(f"  Port {port}: {count} packets\n")
    
    print(f"\nReport saved to {output_file}")

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, count=30)
write_report(captured_packets)

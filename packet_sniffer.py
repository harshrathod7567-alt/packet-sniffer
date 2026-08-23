from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "OTHER"
        
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        else:
            print(f"[{proto}] {src_ip} -> {dst_ip}")

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, count=20)

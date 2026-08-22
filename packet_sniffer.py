from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

print("Starting packet sniffer... Press Ctrl+C to stop.")

sniff(prn=process_packet, count=10)

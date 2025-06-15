from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import time
from collections import defaultdict
import sys
import signal

# Global counter
counters = defaultdict(int)

def analyze_packet(packet):
    try:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f'Proto {proto}')

            counters['total'] += 1
            counters[protocol_name] += 1

            print(f"\n[{timestamp}] {protocol_name} Packet:")
            print(f"  Source IP: {src_ip}")
            print(f"  Destination IP: {dst_ip}")

            if TCP in packet:
                print(f"  Source Port: {packet[TCP].sport}")
                print(f"  Destination Port: {packet[TCP].dport}")
                print(f"  Sequence: {packet[TCP].seq}, Acknowledgment: {packet[TCP].ack}")
            elif UDP in packet:
                print(f"  Source Port: {packet[UDP].sport}")
                print(f"  Destination Port: {packet[UDP].dport}")
            elif ICMP in packet:
                print(f"  ICMP Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")

            if Raw in packet:
                data = packet[Raw].load
                print(f"  Payload: {data[:50]}{'...' if len(data) > 50 else ''}")
            else:
                print("  No Payload")
        else:
            counters['total'] += 1
            counters['Other (Non-IP)'] += 1
            print(f"\n[{timestamp}] Non-IP Packet")
    except Exception as e:
        print(f"Error processing packet: {e}")

def signal_handler(signum, frame):
    print("\n" + "="*50)
    print("PACKET CAPTURE SUMMARY")
    print("="*50)
    print(f"Total Packets: {counters['total']}")
    print(f"TCP Packets: {counters['TCP']}")
    print(f"UDP Packets: {counters['UDP']}")
    print(f"ICMP Packets: {counters['ICMP']}")
    print(f"Other Packets: {counters['Other (Non-IP)']}")
    print("="*50)
    print("\nExiting...")
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print("Starting packet capture... Press Ctrl+C to stop.")
    try:
        sniff(prn=analyze_packet, store=0)
    except Exception as e:
        print(f"\nError occurred: {e}")
        signal_handler(signal.SIGINT, None)
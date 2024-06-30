import scapy.all as scapy
import signal
import sys

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"TCP Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    print("Unable to decode TCP payload.")

        elif packet.haslayer(scapy.UDP):
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"UDP Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    print("Unable to decode UDP payload.")

def start_sniffing():
    # Define a signal handler to handle SIGINT (Ctrl+C)
    def signal_handler(sig, frame):
        print("Sniffing stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    print("Starting packet sniffing. Press Ctrl+C to stop.")
    

    # Sniff with a filter (for example, capturing only TCP and UDP traffic)
    scapy.sniff(prn=packet_callback, store=False, filter="ip")

start_sniffing()

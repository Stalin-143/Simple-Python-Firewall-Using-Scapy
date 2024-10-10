import scapy.all as scapy
import logging

logging.basicConfig(filename="firewall_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

BLOCKED_IPS = ["192.168.1.10", "192.168.1.20"]
BLOCKED_PORTS = [80, 443]

def packet_filter(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        if ip_src in BLOCKED_IPS:
            logging.warning(f"Dropped packet from blocked IP: {ip_src}")
            return None

        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            sport = packet.sport
            dport = packet.dport
            if sport in BLOCKED_PORTS or dport in BLOCKED_PORTS:
                logging.warning(f"Dropped packet with blocked port: {sport if sport in BLOCKED_PORTS else dport}")
                return None

    return packet

def start_firewall():
    print("Starting firewall. Press CTRL+C to stop.")
    scapy.sniff(prn=lambda packet: packet_filter(packet), store=0)

start_firewall()

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time

from utils import (
    detect_high_packet_rate,
    detect_sensitive_port_activity,
    detect_protocol_anomaly
)

packet_counts = defaultdict(int)
protocol_counts = defaultdict(int)
port_access = defaultdict(int)


def analyze_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        packet_counts[src] += 1

        if packet.haslayer(TCP):
            protocol_counts["TCP"] += 1
            port_access[(src, packet[TCP].dport)] += 1

        elif packet.haslayer(UDP):
            protocol_counts["UDP"] += 1
            port_access[(src, packet[UDP].dport)] += 1

        elif packet.haslayer(ICMP):
            protocol_counts["ICMP"] += 1


def generate_report():
    print("\n===== NETWORK ANOMALY REPORT =====\n")

    alerts = []

    alerts.extend(detect_high_packet_rate(packet_counts))
    alerts.extend(detect_sensitive_port_activity(port_access))
    alerts.extend(detect_protocol_anomaly(protocol_counts))

    if not alerts:
        print("No anomalies detected.")
        return

    for alert in alerts:
        print(f"ALERT TYPE: {alert['type']}")

        if "ip" in alert:
            print(f"Source IP: {alert['ip']}")

        if "packets" in alert:
            print(f"Packet Count: {alert['packets']}")

        if "port" in alert:
            print(f"Port Accessed: {alert['port']} ({alert['service']})")

        if "ratio" in alert:
            print(f"UDP Traffic Ratio: {alert['ratio']:.2f}")

        print(f"Reason: {alert['reason']}\n")


def start_monitor(duration=30):
    print("Monitoring network traffic for 30 seconds...\n")

    sniff(prn=analyze_packet, timeout=duration)

    generate_report()


if __name__ == "__main__":
    start_monitor()

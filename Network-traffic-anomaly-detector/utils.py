from config import *
def detect_high_packet_rate(packet_counts):
    alerts=[]
    for ip, count in packet_counts.items():
        if count>PACKET_RATE_THRESHOLD:
            alerts.append({
                "type": "High Packet Rate",
                "ip": ip,
                "packets": count,
                "reason": "Possible scanning or flooding activity"
            })
    return alerts

def detect_sensitive_port_activity(port_access):
    alerts=[]
    for (ip, port), activity in port_access.items():
        if port in SUSPICIOUS_PORTS and activity >= PORT_ACTIVITY_THRESHOLD:
            alerts.append({
                "type": "Sensitive Port Access",
                "ip": ip,
                "port": port,
                "service": SUSPICIOUS_PORTS[port],
                "reason": "Potential service probing"
            })
    return alerts


def detect_protocol_anomaly(protocol_counts):
    alerts=[]
    total=sum(protocol_counts.values())
    if total==0:
        return alerts
    udp_ratio=protocol_counts.get("UDP", 0)/total
    if udp_ratio>UDP_ANOMALY_RATIO:
        alerts.append({
            "type": "Protocol Distribution Anomaly",
            "ratio": udp_ratio,
            "reason": "Unusually high UDP traffic"
        })
    return alerts

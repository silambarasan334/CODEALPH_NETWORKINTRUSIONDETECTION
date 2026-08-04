"""
CodeAlpha Cyber Security Internship
Task 4 - Network Intrusion Detection System (NIDS)

Author: Silmbarasan R.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime

# -----------------------------
# CONFIGURATION
# -----------------------------

PACKET_THRESHOLD = 500          # Flood Detection
PORTSCAN_THRESHOLD = 20         # Number of unique ports
BLACKLIST = []                  # Example: ["192.168.1.100"]

# -----------------------------
# VARIABLES
# -----------------------------

packet_counter = defaultdict(int)
port_counter = defaultdict(set)

total_packets = 0
total_alerts = 0

# -----------------------------
# LOGGING
# -----------------------------

def log_alert(message):
    with open("alert_log.txt", "a") as log:
        log.write(f"{datetime.now()} - {message}\n")


# -----------------------------
# ALERT FUNCTION
# -----------------------------

def alert(message):
    global total_alerts
    total_alerts += 1

    print("\n" + "=" * 60)
    print("🚨 ALERT")
    print(message)
    print("=" * 60)

    log_alert(message)


# -----------------------------
# PACKET ANALYSIS
# -----------------------------

def detect(packet):

    global total_packets

    if not packet.haslayer(IP):
        return

    total_packets += 1

    src = packet[IP].src
    dst = packet[IP].dst

    packet_counter[src] += 1

    print("\n--------------------------------------------")
    print(f"Source IP      : {src}")
    print(f"Destination IP : {dst}")

    # -----------------------------
    # Blacklisted IP Detection
    # -----------------------------

    if src in BLACKLIST:
        alert(f"Traffic detected from Blacklisted IP: {src}")

    # -----------------------------
    # ICMP Detection
    # -----------------------------

    if packet.haslayer(ICMP):

        print("Protocol       : ICMP")

        alert(f"ICMP Packet Detected from {src}")

    # -----------------------------
    # TCP Detection
    # -----------------------------

    elif packet.haslayer(TCP):

        print("Protocol       : TCP")

        flags = packet[TCP].sprintf("%TCP.flags%")
        dport = packet[TCP].dport

        print(f"TCP Flags      : {flags}")
        print(f"Destination Port : {dport}")

        port_counter[src].add(dport)

        if "S" in flags:
            alert(f"TCP SYN Packet from {src}")

        # Possible Port Scan

        if len(port_counter[src]) > PORTSCAN_THRESHOLD:
           alert(f"High Network Traffic Detected from {src}")

    # -----------------------------
    # UDP Detection
    # -----------------------------

    elif packet.haslayer(UDP):

        print("Protocol       : UDP")

        dport = packet[UDP].dport

        print(f"Destination Port : {dport}")

    # -----------------------------
    # Flood Detection
    # -----------------------------

    if packet_counter[src] > PACKET_THRESHOLD:
        alert(f"Possible Flood Attack Detected from {src}")


# -----------------------------
# MAIN PROGRAM
# -----------------------------

print("=" * 60)
print("      NETWORK INTRUSION DETECTION SYSTEM")
print("=" * 60)

print("Monitoring Network Traffic...")
print("Press CTRL + C to stop.\n")

try:

    sniff(prn=detect, store=False)

except KeyboardInterrupt:

    print("\n\nStopping IDS...\n")

    print("=" * 60)
    print("IDS SUMMARY")
    print("=" * 60)

    print(f"Total Packets Analysed : {total_packets}")
    print(f"Total Alerts Generated : {total_alerts}")
    print(f"Unique Source IPs      : {len(packet_counter)}")

    print("\nAlert Log saved to alert_log.txt")

    print("\nThank You.")
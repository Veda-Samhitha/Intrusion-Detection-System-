from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time


icmp_counter = defaultdict(list)
ICMP_THRESHOLD = 5
ICMP_TIME_WINDOW = 3

def detect_icmp_flood(ip):
    current_time = time.time()
    icmp_counter[ip].append(current_time)
    icmp_counter[ip] = [t for t in icmp_counter[ip] if current_time - t <= ICMP_TIME_WINDOW]
    if len(icmp_counter[ip]) > ICMP_THRESHOLD:
        alert = f" ICMP Flood Detected from IP: {ip}"
        with open("alerts_only_log.txt", "a") as log:
            log.write(alert + "\n")



port_scan_tracker = defaultdict(set)
port_scan_time = defaultdict(list)

PORT_SCAN_THRESHOLD = 2
PORT_SCAN_TIME_WINDOW = 5

def detect_port_scan(ip, port):
    current_time = time.time()
    port_scan_time[ip].append(current_time)
    port_scan_tracker[ip].add(port)

    port_scan_time[ip] = [t for t in port_scan_time[ip] if current_time - t <= PORT_SCAN_TIME_WINDOW]

    
    print(f" Tracking: {ip} hit port {port}. Total ports: {len(port_scan_tracker[ip])}")
    print(f" Checked {len(port_scan_tracker[ip])} ports from {ip}")

    if len(port_scan_tracker[ip]) > PORT_SCAN_THRESHOLD and len(port_scan_time[ip]) >= PORT_SCAN_THRESHOLD:
        alert = f" Port Scan Detected from IP: {ip}"
        with open("alerts_only_log.txt", "a", encoding="utf-8") as log:
            log.write(alert + "\n")
            log.flush()


def packet_callback(packet):
    
    if packet.haslayer(ICMP):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            detect_icmp_flood(src_ip)

    
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        print(f" Tracking: {src_ip} hit port {dst_port}.")
        detect_port_scan(src_ip, dst_port)



print("[*] Starting Smart IDS with Port Scan + ICMP Flood Detection...")
sniff(prn=packet_callback, store=0)

**Intrusion-Detection-System**
A Python-based IDS that detects ICMP flood attacks and TCP port scans in real-time using Scapy, with alerts logged and visual ICMP proof captured via Wireshark.
It also includes:
- 📄 Real-time alerts saved in a log file
- 🖥️ A separate `alerts_only.py` file for live monitoring of alerts
- 🦈 Wireshark `.pcapng` file to visualize ICMP traffic

📁 **Project Structure**
Smart_IDS_Project/

├── smart_ids.py # Main IDS with ICMP + Port Scan detection 

├── alerts_only.py # Real-time display of alerts from log file 

├── alerts_only_log.txt # Log file storing detected attacks 

├── icmp loopback capture.pcapng # Wireshark capture of ICMP packets 


**How It Works**

### 1. Packet Sniffing (Scapy)
- Captures live packets using `scapy`
- Analyzes for ICMP floods and TCP port scan behavior

### 2. ICMP Flood Detection
- Tracks the number of pings (ICMP packets) per IP within a short window
- Triggers alert if threshold is crossed

### 3. TCP Port Scan Detection
- Tracks how many **unique ports** an IP hits within 5 seconds
- If more than 2, it logs a port scan alert

### 4. Logging + Real-time Monitoring
- Alerts are written to `alerts_only_log.txt`
- You can monitor new alerts live using `alerts_only.py`



## 🧪 How to Simulate Attacks

### ➤ Simulate Port Scan using `nmap`:
nmap -p 21,22,23,25,80,110,443,8080 127.0.0.1

### ➤ Simulate ICMP Flood using ping:
ping 127.0.0.1 -t -l 1000
This sends continuous ping requests (ICMP Echo) to your own system, simulating a flood attack.
Use Wireshark with the loopback adapter and icmp filter to visually confirm the attack traffic.



### **Programming Language**:

Python 3.6+ - scapy (For packet sniffing and protocol analysis)


### **Cybersecurity Concepts**:

Intrusion Detection System (IDS)

ICMP Flood Detection (Ping Flood)

TCP Port Scan Detection

Threshold-based alert logic

Real-time monitoring & alert logging

### **Tools for Simulation & Testing**:

nmap – To simulate port scanning attacks

ping – To simulate ICMP flood attacks (ping -t -l 1000)

Wireshark – For capturing and visualizing ICMP traffic

### **Editor & Platform**:

Visual Studio Code (VS Code)

Command Prompt (CMD)

Windows OS (with administrator privileges)

### **Files in the Project**:
- `smart_ids.py` – Main IDS detection logic
- `alerts_only.py` – Real-time alert monitor
- `alerts_only_log.txt` – Logged alerts output
- `icmp loopback capture.pcapng` – Wireshark ICMP flood capture

### 📄 Note:
The file alerts_only_log.txt will be automatically created when you run smart_ids.py.
It stores all detected intrusion alerts in real-time.



# Basic Network Sniffer in Python

This project demonstrates a basic network sniffer built using Python and Scapy. It captures and analyzes IP packets to help understand how data flows through a network.

#Objective
To build a simple Python-based packet sniffer that:
- Captures live network traffic
- Extracts source and destination IP addresses
- Displays the transport protocol in use (TCP, ICMP, etc.)
- Applies protocol filtering (TCP and ICMP)

#Tools & Environment
- **OS:** Ubuntu (in Oracle VirtualBox)
- **Language:** Python 3.12
- **Library:** Scapy
- **Environment:** Python Virtual Environment (venv)
- **Privileges:** Root (sudo) required for sniffing

#Setup & Installation

#Step 1: Install Guest Additions (if copy-paste isn’t working)

cd /media/$USER/VBox_GAs*
sudo ./VBoxLinuxAdditions.run


# Step 2: Set up Python virtual environment

python3 -m venv scapy-env
source scapy-env/bin/activate


# Step 3: Install Scapy inside venv

pip install scapy


# Step 4: Create and run the sniffer script
Save the below code as sniffer.py

# Version 1: Capture all IP traffic [Note: The Python script used in this project was adapted from publicly available educational resources and tutorials for learning purposes.]
python
from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"[*] Packet: {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto}")

print("Sniffing started...")
sniff(prn=process_packet, store=False)

# Version 2: Filter only TCP and ICMP packets[Note: The Python script used in this project was adapted from publicly available educational resources and tutorials for learning purposes.]

from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"[*] Packet: {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto}")

print("Sniffing started...")
sniff(filter="tcp or icmp", prn=process_packet, store=False)
```

# Sample Output

[*] Packet: 10.0.2.6 -> 91.189.91.97 | Protocol: 6
[*] Packet: 91.189.91.97 -> 10.0.2.6 | Protocol: 6


# What You Learn
- Working with raw packets using Scapy
- Understanding protocol numbers (e.g., 6 = TCP, 17 = UDP)
- Setting up isolated Python environments
- Root permissions for raw socket operations

#Conclusion
You’ve built and tested a fully functional network sniffer that inspects live traffic on your virtual machine. This project gives a hands-on start to learning network forensics and packet analysis.
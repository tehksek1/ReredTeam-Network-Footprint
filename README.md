# ReredTeam-Network-Footprint
Beginner red team lab projects: Nmap scans, DHCP/DNS spoofing, Scapy scripting, Wireshark traffic analysis, and firewall evasion.
# 🛡️ Red Team Phase 1 Labs

Welcome to my beginner red team portfolio!  
This repository contains hands-on labs and scripts focusing on network-level offensive security, including scanning, protocol spoofing, scripting, and evasion techniques.

---

## 📚 Topics Covered

- **Basic Red Team Concepts** — Understanding offensive security roles and methodology  
- **Lab Environment Setup** — Virtual Machines, network configs, and tools  
- **OSI Model** — Network layers and their importance in attacks  
- **TCP & UDP Scanning** — Port scanning using Python and Nmap  
- **DHCP IP Assignment** — Custom DHCP Discover packets with Scapy  
- **DNS Spoofing & Resolution** — Querying and spoofing DNS with Python/Scapy  
- **Nmap GUI Scanner** — Python script for interactive scanning with GUI  
- **Evasion Techniques** — Bypassing detection tools like KFSensor  
- **Wireshark Analysis** — Capturing and analyzing scan packets  

---

## 🚀 Tools Used

- Python 3 (Scapy, Tkinter)  
- Nmap  
- Wireshark  
- VirtualBox / VMWare  
- Kali Linux (Attacker VM)  

---

## 📂 Repository Structure

```text
RedTeam-Phase1-Labs/
├── 01-Basic-Red-Team-Concepts/

├── 02-Lab-Environment/
install linux
on vm
configured nat environment into it

├── 03-OSI-Model/

Lets start 
🔁 OSI Model vs TCP/IP Stack: Combined Cheat Sheet
OSI Layer	TCP/IP Layer	Key Functions	Examples / Protocols
7. Application	Application	User interface, protocols for network services	HTTP, HTTPS, FTP, DNS, SSH, Telnet
6. Presentation	(Merged into App)	Data encoding, encryption, compression	SSL/TLS, Base64, ASCII, JPEG, MPEG
5. Session	(Merged into App)	Session management, authentication, API calls	NetBIOS, RPC, SOCKS, Session Tokens
4. Transport	Transport	Reliable or unreliable transport, flow control	TCP, UDP, TLS, Port numbers
3. Network	Internet	Logical addressing, routing, packet forwarding	IP, ICMP, ARP, OSPF, BGP
2. Data Link	Network Access	MAC addressing, frame transmission, error detection	Ethernet, Wi-Fi (802.11), PPP, VLANs
1. Physical	(Part of Net Access)	Hardware transmission of raw bits	Cables, Hubs, Radio waves, NICs
________________________________________
💡 How to Use This as a Red Teamer
•	Layers 7–5 (Application Focus): Web hacking, phishing, API abuse.
•	Layer 4 (Transport): Port scanning, firewall evasion, session hijacking.
•	Layer 3 (Network): IP spoofing, ICMP tunnels, VPNs.
•	Layer 2 (Data Link): MITM attacks, MAC spoofing, ARP poisoning.
•	Layer 1 (Physical): Physical intrusions, rogue devices, USB drops.

├── 04-TCP-UDP-Scan/
tcp and udp scan
![image](https://github.com/user-attachments/assets/5f914756-3a06-4304-80ec-59c1a5113c12)

🖥️ Lab Setup:
•	Client IP: 192.168.229.128
•	Server IP: 34.223.124.45
•	Wireshark Filter Used: tcp.flags.syn==1 || tcp.flags.ack==1
•	Target Port: 80 (HTTP)
•	Tool Used: Wireshark (Running on Kali VM)
________________________________________
📸 Screenshot:  
________________________________________
📦 Packet Analysis Table:
Step	Packet No.	Source IP	Destination IP	Flags	Description
1️⃣	3	192.168.229.128	34.223.124.45	SYN	Client initiates connection
2️⃣	10	34.223.124.45	192.168.229.128	SYN, ACK	Server acknowledges and responds
3️⃣	11	192.168.229.128	34.223.124.45	ACK	Client finalizes connection setup
________________________________________
📋 Detailed Packet Info:
Packet 1 (SYN):
•	Src Port: 45450 → Dst Port: 80
•	Flags: SYN
•	Seq: 0
•	Win Size: 64240
Packet 2 (SYN-ACK):
•	Src Port: 80 → Dst Port: 45450
•	Flags: SYN, ACK
•	Seq: 0
•	Ack: 1
•	Win Size: 64240
Packet 3 (ACK):
•	Src Port: 45450 → Dst Port: 80
•	Flags: ACK
•	Seq: 1
•	Ack: 1
•	Win Size: 64240


├── 05-DHCP-IP-Assignment/

├── 06-DNS-Resolution-Spoofing/

├── 07-Nmap-Scan-with-GUI/

python3 -m venv ~/nmap-env
source ~/nmap-env/bin/activate
pip install python-nmap
python nmapbasicsript.py

NMAP BASIC SCRIPT 
#!/usr/bin/env python3

import nmap
import os
from datetime import datetime

# Set target IPs here
target_ips = ['150.1.7.106', '150.1.7.100']

# Nmap scanner
scanner = nmap.PortScanner()

# Output file path (Kali Desktop)
desktop_path = os.path.expanduser('~/Desktop')
timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
report_file = os.path.join(desktop_path, f'nmap_report_{timestamp}.txt')

# Start scanning
with open(report_file, 'w') as report:
    report.write(f"Nmap Scan Report - {timestamp}\n")
    report.write("="*50 + "\n")

    for ip in target_ips:
        report.write(f"\nScanning {ip}...\n")
        try:
            scanner.scan(ip, arguments='-A')
            for host in scanner.all_hosts():
                report.write(f"\nHost: {host} ({scanner[host].hostname()})\n")
                report.write(f"State: {scanner[host].state()}\n")
                
                for proto in scanner[host].all_protocols():
                    report.write(f"Protocol: {proto}\n")
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        state = scanner[host][proto][port]['state']
                        name = scanner[host][proto][port]['name']
                        report.write(f"  Port {port}: {name} - {state}\n")
        except Exception as e:
            report.write(f"Error scanning {ip}: {str(e)}\n")

print(f"[+] Report saved to: {report_file}")

├── 08-Evasion-Techniques/


FULL UPDATED SCRIPT IN WHICH YOU WE CAN BYPASS THE FIREWALL USING CHRIMTIS FORMAT 

 it can bypass kfsensor  
📜 Full Script: nmap_menu_ui.py
python
CopyEdit
import curses
import nmap

# Color constants
COLOR_OPEN = 1
COLOR_CLOSED = 2
COLOR_UNKNOWN = 3

def run_scan(stdscr, ip, ports, scan_type, arguments):
    stdscr.clear()
    stdscr.addstr(0, 0, f"Running {scan_type} on {ip}:{ports}...\n", curses.A_BOLD)
    stdscr.refresh()

    nm = nmap.PortScanner()
    try:
        result = nm.scan(ip, ports, arguments=arguments)

        stdscr.addstr(2, 0, f"[+] Nmap Arguments: {arguments}")
        if ip in result['scan']:
            scan_data = result['scan'][ip].get('tcp', {})
            if not scan_data:
                stdscr.addstr(4, 0, "[-] No open ports found or port is filtered.")
            else:
                line = 5
                for port, data in scan_data.items():
                    state = data.get('state', 'unknown')
                    if state == 'open':
                        color = COLOR_OPEN
                    elif state == 'closed':
                        color = COLOR_CLOSED
                    else:
                        color = COLOR_UNKNOWN
                    stdscr.addstr(line, 0, f"Port {port}/tcp is {state}", curses.color_pair(color))
                    line += 1
        else:
            stdscr.addstr(4, 0, "[-] Host is down or blocked the scan.")
    except Exception as e:
        stdscr.addstr(4, 0, f"[!] Error: {str(e)}")

    stdscr.addstr(20, 0, "\nPress any key to return to the main menu.")
    stdscr.refresh()
    stdscr.getch()


def host_discovery(stdscr, ip_range):
    stdscr.clear()
    stdscr.addstr(0, 0, f"Running Host Discovery on {ip_range}...\n", curses.A_BOLD)
    stdscr.refresh()

    nm = nmap.PortScanner()
    try:
        result = nm.scan(hosts=ip_range, arguments='-sn')
        hosts = result.get('scan', {})
        line = 2
        for host in hosts:
            state = hosts[host]['status']['state']
            color = COLOR_OPEN if state == 'up' else COLOR_CLOSED
            stdscr.addstr(line, 0, f"{host} is {state}", curses.color_pair(color))
            line += 1
        if not hosts:
            stdscr.addstr(3, 0, "[-] No hosts discovered.")
    except Exception as e:
        stdscr.addstr(3, 0, f"[!] Error: {str(e)}")

    stdscr.addstr(20, 0, "\nPress any key to return to the main menu.")
    stdscr.refresh()
    stdscr.getch()


def main(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(COLOR_OPEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(COLOR_CLOSED, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(COLOR_UNKNOWN, curses.COLOR_YELLOW, curses.COLOR_BLACK)

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "🔍 Nmap Automation Scanner - Terminal UI", curses.A_BOLD | curses.A_UNDERLINE)
        stdscr.addstr(2, 0, "Select a scan preset:")
        stdscr.addstr(4, 2, "1. Web Scan (80,443)           - TCP Connect")
        stdscr.addstr(5, 2, "2. Stealth Scan (1-1000)       - SYN Scan")
        stdscr.addstr(6, 2, "3. Firewall Evasion            - Xmas / Null / FIN")
        stdscr.addstr(7, 2, "4. Full TCP Scan (1-65535)     - TCP Connect")
        stdscr.addstr(8, 2, "5. Custom Scan                 - Enter IP, Ports, Flags")
        stdscr.addstr(9, 2, "6. Host Discovery              - Ping Sweep (-sn)")
        stdscr.addstr(10, 2, "7. Exit")

        stdscr.refresh()
        choice = stdscr.getch()

        if choice == ord('7'):
            break

        # Get target IP
        stdscr.clear()
        if choice == ord('6'):
            stdscr.addstr(0, 0, "Enter IP range or subnet for host discovery (e.g., 192.168.1.0/24): ")
        else:
            stdscr.addstr(0, 0, "Enter Target IP: ")
        curses.echo()
        ip = stdscr.getstr(1, 0, 40).decode().strip()
        curses.noecho()

        if choice == ord('1'):  # Web Scan
            run_scan(stdscr, ip, "80,443", "Web Scan", "-sT")
        elif choice == ord('2'):  # Stealth Scan
            run_scan(stdscr, ip, "1-1000", "Stealth SYN Scan", "-sS")
        elif choice == ord('3'):  # Firewall Evasion
            stdscr.clear()
            stdscr.addstr(0, 0, "Select Firewall Evasion Type:")
            stdscr.addstr(2, 2, "1. Xmas Scan (-sX)")
            stdscr.addstr(3, 2, "2. Null Scan (-sN)")
            stdscr.addstr(4, 2, "3. FIN Scan (-sF)")
            stdscr.refresh()
            evasion = stdscr.getch()

            scan_map = {'1': '-sX', '2': '-sN', '3': '-sF'}
            scan_type = {'1': 'Xmas Scan', '2': 'Null Scan', '3': 'FIN Scan'}

            scan_flag = scan_map.get(chr(evasion), '-sX')
            scan_name = scan_type.get(chr(evasion), 'Xmas Scan')
            run_scan(stdscr, ip, "1-1000", scan_name, scan_flag)
        elif choice == ord('4'):  # Full TCP Scan
            run_scan(stdscr, ip, "1-65535", "Full TCP Connect", "-sT")
        elif choice == ord('5'):  # Custom
            stdscr.clear()
            stdscr.addstr(0, 0, "Enter Port(s) (e.g., 22,80 or 1-1000): ")
            curses.echo()
            ports = stdscr.getstr(1, 0, 40).decode().strip()

            stdscr.addstr(3, 0, "Enter Nmap Flags (e.g., -sS -Pn -T4): ")
            arguments = stdscr.getstr(4, 0, 60).decode().strip()
            curses.noecho()

            run_scan(stdscr, ip, ports, "Custom", arguments)
        elif choice == ord('6'):  # Host Discovery
            host_discovery(stdscr, ip)

curses.wrapper(main)
🧪 How to Run
1.	Save as nmap_menu_ui.py
2.	Install Python Nmap if needed:
bash
CopyEdit
pip install python-nmap
3.	Run with:
bash
CopyEdit
python3 nmap_menu_ui.py

✅ DNS Lookup Lab (from VM → Linux Host or Internet)
________________________________________

├── 09-Wireshark-Scan-Analysis/

🌐 DNS (Domain Name System)
Definition:
DNS translates domain names (like google.com) into IP addresses (like 142.250.64.110) so computers can communicate.
📦 DHCP (Dynamic Host Configuration Protocol)
Definition:
DHCP automatically assigns IP addresses, subnet masks, default gateways, and DNS servers to devices on a network
![image](https://github.com/user-attachments/assets/d8eccba2-7123-435b-9a92-8e41cdbba57f)

✅ Step-by-Step Code: dns_gui.py
python
CopyEdit
import tkinter as tk
from tkinter import scrolledtext
import dns.resolver
from scapy.all import *

# ----------------- DNS Query Function -----------------
def perform_dns_query():
    domain = dns_entry.get()
    output_box.insert(tk.END, f"\n[DNS] Querying {domain}...\n")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ip in result:
            output_box.insert(tk.END, f" - {domain} → {ip}\n")
    except Exception as e:
        output_box.insert(tk.END, f"[!] DNS Error: {e}\n")

# ----------------- DHCP Discover Function -----------------
def send_dhcp_discover():
    output_box.insert(tk.END, "\n[DHCP] Sending DHCP Discover...\n")
    try:
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC(), type=0x0800)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=RandMAC().raw(), xid=RandInt(), flags=0x8000)
        dhcp = DHCP(options=[("message-type", "discover"), ("end")])
        packet = ethernet / ip / udp / bootp / dhcp

        sendp(packet, iface=iface_entry.get(), verbose=0)
        output_box.insert(tk.END, "[+] DHCP Discover sent successfully.\n")
    except Exception as e:
        output_box.insert(tk.END, f"[!] DHCP Error: {e}\n")

# ----------------- GUI Setup -----------------
window = tk.Tk()
window.title("DNS & DHCP Toolkit")
window.geometry("600x400")

tk.Label(window, text="DNS Domain:").pack()
dns_entry = tk.Entry(window, width=50)
dns_entry.pack()

tk.Button(window, text="Run DNS Lookup", command=perform_dns_query).pack(pady=5)

tk.Label(window, text="Network Interface (e.g. eth0):").pack()
iface_entry = tk.Entry(window, width=50)
iface_entry.insert(0, "eth0")
iface_entry.pack()

tk.Button(window, text="Send DHCP Discover", command=send_dhcp_discover).pack(pady=5)

output_box = scrolledtext.ScrolledText(window, width=70, height=15)
output_box.pack()

window.mainloop()
________________________________________
🔧 Run This App
Install dependencies if not already done:
bash
CopyEdit
pip install dnspython scapy
Run with elevated permissions:
bash
CopyEdit
sudo python3 dns_dhcp_gui.py
└── README.md

________________________________________







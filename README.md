# Network_scanner

# 🔍 Advanced Network Scanner (Tkinter + Scapy GUI)

A graphical network scanner built in Python, designed to detect live hosts on a network using ARP scanning and perform TCP SYN-based port scanning with basic service fingerprinting. It features a user-friendly GUI interface for better usability and real-time results—ideal for learning, home labs, or showcasing cybersecurity fundamentals.

## 🧠 Project Highlights

- Built with `Tkinter` for the GUI and `Scapy` for low-level network scanning
- Detects **live devices** in a subnet using ARP ping
- Scans **common ports** using TCP SYN method
- Performs **banner grabbing** to fingerprint open ports
- Displays results in a clear, **table-style view**
- Identifies device vendors using MAC OUI prefixes
- Built with real-time logging and color-coded output for visibility

---

## 📸 Screenshots

| Main GUI | Scan Results |
|----------|--------------|
| ![Main GUI](screenshots/main_gui.png) | ![Scan Results](screenshots/scan_results.png) |

---

## ⚙️ How It Works

1. **User inputs subnet range** (e.g., `192.168.1.0/24`)
2. **ARP Ping Scan** is used to discover live hosts
3. Each live host is scanned on common ports (e.g., 22, 80, 443)
4. Detected services are **fingerprinted via banner grabbing**
5. MAC address is mapped to vendor (if available)
6. Results are displayed in a sortable GUI table

---

## 🧰 Requirements

- Python 3.x
- Scapy
- Tkinter (usually pre-installed with Python)
- Run with `sudo` or as Administrator for proper packet-level access

Install dependencies (if needed):
```bash
pip install scapy

🚀 Usage
```bash
sudo python3 network_scanner.py

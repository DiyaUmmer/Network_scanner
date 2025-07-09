#!/usr/bin/env python3
from scapy.all import *
import ipaddress
import argparse
import socket
import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, scrolledtext, font
from tkinter import messagebox

class NetworkScannerGUI:
    def __init__(self):
        self.results = {}
        self.root = tk.Tk()
        self.setup_gui()
        
        # Common ports to scan (you can modify this list)
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]
        
    def setup_gui(self):
        """Configure the GUI interface"""
        self.root.title("Advanced Network Scanner")
        self.root.geometry("800x600")  # Wider window for better output
        
        # Make the window resizable
        self.root.minsize(700, 500)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Custom fonts
        title_font = font.Font(family="Helvetica", size=12, weight="bold")
        button_font = font.Font(family="Helvetica", size=10)
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.columnconfigure(0, weight=1)
        
        # Title label
        title_label = ttk.Label(
            main_frame, 
            text="Network Scanner", 
            font=title_font,
            foreground="#2c3e50"
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Scan Parameters", padding="10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Target IP range
        ttk.Label(input_frame, text="Target IP Range:").grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(input_frame, width=25)
        self.target_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.target_entry.insert(0, "192.168.1.0/24")
        
        # Scan button
        self.scan_btn = ttk.Button(
            input_frame, 
            text="Start Scan", 
            command=self.start_scan,
            style="Accent.TButton"
        )
        self.scan_btn.grid(row=0, column=2, padx=10)
        
        # Output area with colored tags
        output_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        output_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_area = tk.Text(
            output_frame, 
            wrap=tk.NONE,  # Changed to NONE for table-like display
            width=80, 
            height=20,
            font=('Consolas', 10),
            bg="#f5f5f5",
            padx=10,
            pady=10
        )
        self.output_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(output_frame, command=self.output_area.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.output_area['yscrollcommand'] = scrollbar.set
        
        # Configure tags for colored output
        self.output_area.tag_config("success", foreground="green")
        self.output_area.tag_config("error", foreground="red")
        self.output_area.tag_config("warning", foreground="orange")
        self.output_area.tag_config("info", foreground="blue")
        self.output_area.tag_config("header", foreground="purple", font=('Consolas', 10, 'bold'))
        self.output_area.tag_config("host", foreground="#2c3e50", font=('Consolas', 10, 'bold'))
        self.output_area.tag_config("port", foreground="#3498db")
        self.output_area.tag_config("vendor", foreground="#e74c3c")
        self.output_area.tag_config("table_header", foreground="black", font=('Consolas', 10, 'bold'), background="#e0e0e0")
        self.output_area.tag_config("table_row", foreground="black", font=('Consolas', 10))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.grid(row=3, column=0, sticky=(tk.W, tk.E))
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("Accent.TButton", foreground="white", background="#3498db")
        
    def log(self, message, tag=None):
        """Add message to output area with optional color tag"""
        self.output_area.insert(tk.END, message + "\n", tag)
        self.output_area.see(tk.END)
        self.root.update()
        
    def display_results_table(self):
        """Display results in a table-like format"""
        # Clear previous results
        self.output_area.delete(1.0, tk.END)
        
        # Table header
        header = f"{'IP Address':<15} | {'MAC Address':<17} | {'Vendor':<20} | {'Open Ports'}\n"
        self.output_area.insert(tk.END, header, "table_header")
        self.output_area.insert(tk.END, "-"*80 + "\n", "table_header")
        
        # Table rows
        for ip, data in self.results.items():
            ports = ", ".join(str(p) for p in data["ports"].keys())
            row = f"{ip:<15} | {data['mac']:<17} | {data['vendor'][:20]:<20} | {ports}\n"
            self.output_area.insert(tk.END, row, "table_row")
        
        self.output_area.see(tk.END)
        
    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)
        self.root.update()
        
    def get_mac_vendor(self, mac):
        """Get vendor from MAC address (simplified)"""
        oui = mac[:8].upper()
        vendor_db = {
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:1C:42": "Parallels",
            "00:1C:14": "Dell",
            "00:24:E8": "Dell",
            "00:26:B9": "Apple",
            "8C:C7:C3": "Huawei",
            "EA:15:C9": "Amazon",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi"
        }
        return vendor_db.get(oui, "Unknown Vendor")

    def validate_ip_range(self, ip_range):
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError as e:
            self.log(f"Invalid IP range: {ip_range}\nError: {e}", "error")
            return []

    def arp_ping_scan(self, ip_list, timeout=2):
        """ARP-based host discovery"""
        try:
            answered, _ = arping(ip_list, timeout=timeout, verbose=False)
            for sent, received in answered:
                vendor = self.get_mac_vendor(received.hwsrc)
                self.results[received.psrc] = {
                    "mac": received.hwsrc,
                    "ports": {},
                    "vendor": vendor
                }
            return self.results.keys()
        except Exception as e:
            self.log(f"ARP scan failed: {e}", "error")
            return []

    def tcp_port_scan(self, ip, ports, timeout=1):
        """TCP SYN scan"""
        open_ports = []
        for port in ports:
            try:
                packet = IP(dst=ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=timeout, verbose=0)
                if response and response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=0)
            except Exception as e:
                self.log(f"Error scanning {ip}:{port} - {e}", "warning")
        return open_ports

    def service_fingerprint(self, ip, port):
        """Basic service identification"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                if port == 80 or port == 443:
                    s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                else:
                    s.send(b"\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner.split('\n')[0] if banner else "No banner"
        except:
            return "No response"

    def start_scan(self):
        """Start the scanning process"""
        self.results = {}
        self.output_area.delete(1.0, tk.END)
        target = self.target_entry.get()
        
        self.scan_btn.config(state=tk.DISABLED)
        self.update_status("Scanning... Please wait")
        
        try:
            ip_list = self.validate_ip_range(target)
            if not ip_list:
                return
                
            self.log(f"Starting scan of {len(ip_list)} IP addresses...", "header")
            
            live_hosts = self.arp_ping_scan(ip_list)
            self.log(f"\nFound {len(live_hosts)} active hosts, scanning ports...", "header")
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                for host in live_hosts:
                    self.log(f"\nScanning host: {host}", "host")
                    open_ports = self.tcp_port_scan(host, self.common_ports)
                    
                    if open_ports:
                        for port in open_ports:
                            service = self.service_fingerprint(host, port)
                            self.results[host]["ports"][port] = service
                    else:
                        self.log("  No open ports found", "warning")
            
            # Display results in table format
            self.display_results_table()
            self.log("\nScan complete!", "success")
            self.update_status("Scan completed successfully")
            
        except Exception as e:
            self.log(f"\nScan failed: {e}", "error")
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{str(e)}")
        finally:
            self.scan_btn.config(state=tk.NORMAL)

def main():
    # Check if running with root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    # Run the GUI
    scanner = NetworkScannerGUI()
    scanner.root.mainloop()

if __name__ == "__main__":
    main()
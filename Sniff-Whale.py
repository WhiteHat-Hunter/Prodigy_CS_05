# Sniff-Whale - A Network Packet Analyzer Tool in Python By ~ Siddhesh Surve
# An Internship Based Task_5

import time
import dpkt
from datetime import datetime
import socket
from colorama import Fore
from colorama import Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
import platform
import os
import pyfiglet
import logging
import io
from contextlib import redirect_stdout

def clear_screen():
    # Clears the console screen based on the operating system.
    if os.name == 'nt':
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Unix/Linux/Mac

def print_banner():
    # Prints the banner for the Sniff-Whale tool with ASCII art.
    clear_screen()
    if os.name == 'nt':
        fig = pyfiglet.figlet_format("Sniff - Whale", font="banner3-D", width=120)
        print("\n")
        print(fig)
        fig2 = pyfiglet.figlet_format("By - MR.SIDDHESH", font="digital")
        print(fig2)
    else:
        fig = pyfiglet.figlet_format("Sniff - Whale", font="standard", width=100)
        print("\n")
        print(fig)
        fig2 = pyfiglet.figlet_format("By - MR.SIDDHESH", font="standard")
        print(fig2)


# Configure logging
logging.basicConfig(filename = datetime.now().strftime("%d-%m-%Y_Analyzed-Packets.log"), level=logging.INFO, 
                    format='%(message)s')

print_banner()

choice = "Y"

def get_current_mac(interface):
    # Retrieves the current MAC address of a network interface.
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["ipconfig", "/all"], text=True)
            mac_pattern = re.compile(r"Physical\s+Address[^\w]*([\w-]{17})", re.MULTILINE)
        elif platform.system() == "Linux":
            output = subprocess.check_output(["ifconfig"], text=True)
            mac_pattern = re.compile(r"HWaddr\s+([\w:]{17})", re.MULTILINE)
        else:
            raise EnvironmentError("Unsupported OS")
        
        match = mac_pattern.search(output)
        return match.group(1) if match else "No MAC found"
    except Exception as e:
        logging.info(f"Error: {e}")
        print(f"Error: {e}")
        return "Error"

def get_current_ip(interface):
    # Retrieves the current IP address of a network interface.
    try:
        output = subprocess.check_output(["ipconfig"], text=True)
        ip_pattern = re.compile(r"IPv4 Address[^\w]*([\d\.]+)", re.MULTILINE)
        match = ip_pattern.search(output)
        return match.group(1) if match else "No IP found"
    except Exception as e:
        logging.info(f"Error: {e}")
        print(f"Error: {e}")
        return "Error"

def ip_table():
    # Displays a table of network interfaces with their MAC and IP addresses.
    addrs = psutil.net_if_addrs()
    t1 = PrettyTable(['Interface', 'Mac Address', 'IP Address'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t1.add_row([k, mac, ip])
        elif mac:
            t1.add_row([k, mac, "No IP assigned"])
        elif ip:
            t1.add_row([k, "No MAC assigned", ip])
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    logging.info(t1)
    print(t)

def sniff(interface):
    # Starts sniffing on the specified network interface and processes packets.
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    # Processes each sniffed packet to identify HTTP/HTTPS requests and other details.
    # Check for HTTP Requests
    if packet.haslayer(http.HTTPRequest):
        logging.info("[+] HTTP REQUEST >>>>>")
        print("\n[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        test = get_login_info(packet)
        if test:
            logging.info(f"[+] Username OR password is Sent >>>> {test}")
            print(f"{Fore.GREEN}[+] Username OR password is Send >>>> {test} {Style.RESET_ALL}")
        if choice.lower() == "y":
            raw_http_request(packet)
    
    # Check for HTTPS Requests
    elif packet.haslayer(scapy.all.IP):
        ip_layer = packet.getlayer(scapy.all.IP)
        if packet.haslayer(scapy.all.TCP):
            tcp_layer = packet.getlayer(scapy.all.TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            if dst_port == 443 or src_port == 443:
                logging.info("[+] HTTPS REQUEST >>>>>")
                logging.info(f"HTTPS traffic from {src_ip} to {dst_ip}")
                print("\n[+] HTTPS REQUEST >>>>>")
                print(f"HTTPS traffic from {src_ip} to {dst_ip}")
                if hasattr(tcp_layer, 'payload'):
                    tls_payload = bytes(tcp_layer.payload)
                    sni = extract_sni_from_tls(tls_payload)
                    if sni:
                        logging.info(f"SNI (Server Name Indication): {sni}")
                        print(f"SNI (Server Name Indication): {sni}")
                    else:
                        logging.info("No SNI found in the packet")
                        print("No SNI found in the packet")
            
            # Print TCP packet details
            logging.info(f"[+] TCP Packet >>>>> Source Port: {src_port}, Destination Port: {dst_port}")
            print(f"\n[+] TCP Packet >>>>> Source Port: {src_port}, Destination Port: {dst_port}")
        
        # Print UDP packet details
        if packet.haslayer(scapy.all.UDP):
            udp_layer = packet.getlayer(scapy.all.UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            print(f"\n[+] UDP Packet >>>>> Source Port: {src_port}, Destination Port: {dst_port}")
            logging.info(f"[+] UDP Packet >>>>> Source Port: {src_port}, Destination Port: {dst_port}")

def get_login_info(packet):
    # Extracts and returns login information from a packet if present.
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        load_decode = load.decode(errors='ignore')
        keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
        for keyword in keywords:
            if keyword in load_decode:
                return load_decode
    return None

def url_extractor(packet):
    # Extracts and prints URL and other HTTP request details from a packet.
    print("\nPacket Details:")
    packet.show()
    with io.StringIO() as buf, redirect_stdout(buf):
        packet.show() 
        packet_details = buf.getvalue()
    logging.info("Packet Details:\n" + packet_details)
    http_layer = packet.getlayer(http.HTTPRequest)
    if http_layer:
        ip_layer = packet.getlayer(scapy.all.IP)
        if ip_layer:
            src_ip = ip_layer.fields.get("src", "Unknown Source IP")
            method = http_layer.fields.get("Method", b"Unknown Method").decode(errors='ignore')
            host = http_layer.fields.get("Host", b"Unknown Host").decode(errors='ignore')
            path = http_layer.fields.get("Path", b"Unknown Path").decode(errors='ignore')
            logging.info(f"\n{src_ip} just requested \n{method} {host} {path}")
            print(f"\n{src_ip} just requested \n{method} {host} {path}")
        else:
            logging.info("No IP layer found in the packet.")
            print("No IP layer found in the packet.")
    else:
        logging.info("No HTTP layer found in the packet.")
        print("No HTTP layer found in the packet.")

def raw_http_request(packet):
    # Prints raw HTTP request data from a packet.
    httplayer = packet[http.HTTPRequest].fields
    logging.info("\n-----------------***Raw HTTP Packet***-------------------")
    print("\n-----------------***Raw HTTP Packet***-------------------")
    logging.info("{:<8} {:<15}".format('Key', 'Label'))
    print("{:<8} {:<15}".format('Key', 'Label'))
    try:
        for k, v in httplayer.items():
            try:
                label = v.decode(errors='ignore')
            except:
                label = "Unknown"
            logging.info("{:<40} {:<15}".format(k, label))
            print("{:<40} {:<15}".format(k, label))
    except KeyboardInterrupt:
        logging.info("\n[+] Quitting Program...")
        print("\n[+] Quitting Program...")
    logging.info("---------------------------------------------------------")
    print("---------------------------------------------------------")

def extract_sni_from_tls(tls_record):
    # Extracts the SNI (Server Name Indication) from a TLS record.
    try:
        records, _ = dpkt.ssl.tls_multi_factory(tls_record)
        for record in records:
            if isinstance(record, dpkt.ssl.TLSClientHello):
                for ext_type, ext_data in record.extensions:
                    if ext_type == 0x00:  # Extension type for SNI
                        sni = ext_data[5:].decode('utf-8', errors='ignore')
                        return sni
    except dpkt.ssl.SSL3Exception as e:
        logging.info(f"SSL3Exception occurred: {e}")
        print(f"SSL3Exception occurred: {e}")
    except dpkt.dpkt.NeedData as e:
        logging.info(f"NeedData exception occurred: {e}")
        print(f"NeedData exception occurred: {e}")
    except Exception as e:
        Logging.info(f"General Exception occurred: {e}")
        print(f"General Exception occurred: {e}")
    return None

def main_sniff():
    logging.info("Sniff-Whale > A Network Packet Analyzer Tool in Python")
    # Main function to start packet analysis and handle user input.
    print(f"{Fore.BLUE}Sniff-Whale > A Network Packet Analyzer Tool in Python, Sniff HTTP Requests, UDP TCP Connections and Login Forms Data!{Style.RESET_ALL}")
    try:
        global choice
        choice = input(f"{Fore.YELLOW}\n[*] Do you want to print the raw Packet : Y/N : {Style.RESET_ALL}")
        ip_table()
        interface = input("\n[*] Please Choose the interface Name : ")
        print(f"{Fore.RED}\n[*] Started Analyzing the Packets...{Style.RESET_ALL}")
        sniff(interface)
        print(f"{Fore.RED}\n[*] Closing the Packet Analyzer...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}\n[!] Closing the Packet Analyzer...{Style.RESET_ALL}")
        time.sleep(3)
    
main_sniff()

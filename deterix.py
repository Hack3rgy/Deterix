# Import Scapy and subprocess
from scapy.all import *
import logging #For Logging
from collections import deque
import subprocess
from datetime import datetime  # Import datetime module for timestamp

ascii_art = """
    ____       __            _     
   / __ \___  / /____  _____(_)_ __
  / / / / _ \/ __/ _ \/ ___/ / |/_/
 / /_/ /  __/ /_/  __/ /  / />  <  
/_____/\___/\__/\___/_/  /_/_/|_|  

                       --Hack3rgy
      The DOS Detection Tool                   
  Follow us on Instagram @Hack3rgy
                     
"""

print(ascii_art)

# Define global variables

window_size = 100 #Change it according to you
threshold = 25 #Change it according to you
ip_counts = {}  # Use a regular dictionary
interface = input('Enter your Network Interface > ')
your_ip = input('Enter your Machine\'s IP Address > ') 
print("Scanning Started:")
log_file = "dos_attack.log" #Change the file name according to you
logging.basicConfig(filename=log_file, level=logging.INFO)

# Define the packet handler function
def packet_handler(packet):
    if IP in packet and packet[IP].dst == your_ip:
        source_ip = packet[IP].src

        # Initialize a deque for each unique source IP if it doesn't exist
        if source_ip not in ip_counts:
            ip_counts[source_ip] = deque(maxlen=window_size)

        ip_counts[source_ip].append(packet)

        # Check if the count for this source IP exceeds the threshold
        if len(ip_counts[source_ip]) > threshold:
            timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            message = f"{timestamp} - Potential DoS Attack Detected from {source_ip}! Packet type: {packet.summary()}"
            print(message)
            logging.info(message)

            # Block the IP using iptables
            iptables_command = f"iptables -A INPUT -s {source_ip} -j DROP"
            try:
                subprocess.run(iptables_command, shell=True, check=True)
                print(f"Blocked IP address: {source_ip}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to block IP address {source_ip}. Error: {e}")

# Start packet capture
sniff(filter=f"tcp and dst host {your_ip}", prn=packet_handler, iface=interface)

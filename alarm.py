#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

# Incident counter
incident_counter = 1

# To track FTP username and password
ftp_credentials = {}

def packetcallback(packet):
    global incident_counter
    global ftp_credentials

    try:
        if packet.haslayer(TCP):
            # NULL scan (no flags set)
            if packet[TCP].flags == 0:
                print(f"ALERT #{incident_counter}: NULL scan is detected from {packet[IP].src} (TCP)!")
                incident_counter += 1

            # FIN scan (FIN flag set, no other flags)
            elif packet[TCP].flags == "F":
                print(f"ALERT #{incident_counter}: FIN scan is detected from {packet[IP].src} (TCP)!")
                incident_counter += 1

            # Xmas scan (FIN, PSH, and URG flags set)
            elif packet[TCP].flags == "FPU":
                print(f"ALERT #{incident_counter}: Xmas scan is detected from {packet[IP].src} (TCP)!")
                incident_counter += 1

            # SMB scanning (Port 445)
            elif packet[TCP].dport == 445:
                print(f"ALERT #{incident_counter}: SMB scan is detected from {packet[IP].src} (TCP 445)!")
                incident_counter += 1

            # RDP scanning (Port 3389)
            elif packet[TCP].dport == 3389:
                print(f"ALERT #{incident_counter}: RDP scan is detected from {packet[IP].src} (TCP 3389)!")
                incident_counter += 1

            # VNC scanning (Port 5900)
            elif packet[TCP].dport == 5900:
                print(f"ALERT #{incident_counter}: VNC scan is detected from {packet[IP].src} (TCP 5900)!")
                incident_counter += 1

        # Detect HTTP traffic for Basic Authentication
        if packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport == 80:
            payload = packet[Raw].load.decode(errors='ignore')
            if "Authorization: Basic" in payload:
                # Extract base64 encoded username:password
                encoded_creds = payload.split("Authorization: Basic ")[1].split("\r\n")[0]
                decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                username, password = decoded_creds.split(':')
                print(f"ALERT #{incident_counter}: HTTP credential is detected from {packet[IP].src} (HTTP) (username:{username}, password:{password})!")
                incident_counter += 1

        # Detect FTP clear-text credentials
        if packet.haslayer(Raw) and packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            payload = packet[Raw].load.decode(errors='ignore')

            # Extract the username and password
            if "USER " in payload:
                ftp_credentials['user'] = payload.split("USER ")[1].strip()
            
            if "PASS " in payload:
                ftp_credentials['pass'] = payload.split("PASS ")[1].strip()

            # If both user and pass have been captured, print the alert and reset the tracker
            if 'user' in ftp_credentials and 'pass' in ftp_credentials:
                print(f"ALERT #{incident_counter}: FTP credential is detected from {packet[IP].src} (FTP) (USER {ftp_credentials['user']}, PASS {ftp_credentials['pass']})!")
                incident_counter += 1
                # Reset after alert is given
                ftp_credentials = {}

        # Nikto scan detection based on specific signature (HTTP User-Agent field)
        if packet.haslayer(Raw) and packet.haslayer(TCP) and packet[TCP].dport == 80:
            payload = packet[Raw].load.decode(errors='ignore')
            
            if "Nikto" in payload:
                # Extract the HTTP request line (e.g., "GET /path HTTP/1.1")
                request_line = payload.split("\r\n")[0]  # Assuming the request line is the first line of the payload
                print(f"ALERT #{incident_counter}: Nikto scan is detected from {packet[IP].src} (HTTP) ({request_line})!")
                incident_counter += 1

    except Exception as e:
        pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")

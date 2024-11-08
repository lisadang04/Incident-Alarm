# The Incident Alarm

## Overview

The Incident Alarm is a Python-based network monitoring tool designed to detect potential vulnerabilities and suspicious activities in network traffic. By analyzing a live stream or pre-recorded PCAP files, this tool identifies scan types (e.g., NULL, FIN, Xmas) and plaintext credentials in common protocols, alerting users of potential security incidents.

## Key Features

- **Scan Detection**: Identifies NULL, FIN, and Xmas scans.
- **Credential Monitoring**: Alerts for plaintext usernames and passwords sent over HTTP Basic Authentication, FTP, and IMAP.
- **Service Scanning Alerts**: Detects scans for SMB, RDP, and VNC services.
- **Nikto Detection**: Identifies Nikto scans based on HTTP User-Agent strings.
- **Real-time or File-based Analysis**: Works with live network interfaces or pre-recorded PCAP files.

## Usage

### Requirements

- **Python** 3
- **Scapy** library
- **Virtualenv** (recommended for isolated environments)

### Setup

1. Clone the repository and navigate to the project directory.
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv env
   source env/bin/activate
   ```
3. Install Scapy:
   ```bash
   pip install scapy
   ```

### Running the Tool

The tool accepts three arguments:

- `-i INTERFACE`: Specify a network interface to sniff on (requires sudo).
- `-r PCAPFILE`: Specify a PCAP file for offline analysis.
- `-h`: Display usage information.

#### Examples

- **Help**: `python3 alarm.py -h`
- **Read from PCAP**: `python3 alarm.py -r <your_pcap_file>.pcap`
- **Sniff live traffic**: `sudo python3 alarm.py -i en0`

#### Exiting

For live sniffing, press `Control-C` to stop.

### Alerts

Alerts are displayed in the following format:

```plaintext
ALERT #{incident_number}: #{incident_type} detected from #{source IP} (#{protocol}) (#{details})!
```

Example:
```plaintext
ALERT #1: Xmas scan is detected from 192.168.1.3 (TCP)!
ALERT #2: HTTP credential detected from 192.168.1.5 (HTTP) (username: admin, password: secret)
```

Notes
- Live network sniffing requires root privileges.
- Virtual environments prevent conflicts with system-wide Python packages.

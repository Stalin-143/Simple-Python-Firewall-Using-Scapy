# Simple Python Firewall Using Scapy

This is a basic firewall script implemented in Python using the [Scapy](https://scapy.net/) library. It demonstrates a simple packet filtering system that blocks incoming or outgoing packets based on specific IP addresses and port numbers. The firewall logs the dropped packets to a log file, providing insights into what traffic is being blocked.

## Features:
- Blocks specific IP addresses from sending/receiving packets.
- Blocks packets with specified source or destination ports (e.g., HTTP/HTTPS traffic).
- Logs dropped packets to a file (`firewall_log.txt`) with timestamps for easy auditing.
- Simple and effective for basic network traffic monitoring and filtering.

## How It Works:
1. The firewall listens for all incoming packets.
2. It inspects the source and destination IP addresses, as well as the transport layer (TCP/UDP) ports.
3. If a packet matches a blocked IP or port, it is dropped and logged.
4. The program uses Scapy's sniffing functionality to capture and inspect packets.

## Configuration:
- **Blocked IPs**: You can configure which IP addresses to block by modifying the `BLOCKED_IPS` list in the script.
- **Blocked Ports**: You can configure which ports to block by modifying the `BLOCKED_PORTS` list in the script.

## Setup:

### 1. Install Dependencies:

Make sure you have Python and `pip` installed. Then install Scapy using:

```bash
pip install scapy
```
### 2. 2. Run the Script:

Run the firewall script with:

```bash

python firewall.py
```

The script will start sniffing the network and blocking traffic according to the specified rules.

## Example Log Output:

The firewall logs dropped packets with timestamps, for example:

```text

2024-10-10 12:34:56,789 - Dropped packet from blocked IP: 192.168.1.10
2024-10-10 12:35:12,023 - Dropped packet with blocked port: 443
```

These logs will be saved in the firewall_log.txt file.
# Notes:

    This script is a basic demonstration and is not recommended for use in production environments.
    You can extend the functionality to support more complex filtering criteria, such as specific protocols, IP ranges, or custom actions.

## License:

This project is open-source and available under the MIT LICENSE.



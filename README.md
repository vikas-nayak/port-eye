# PortEye - A Newtork Scanner

A Python-based network scanning tool that performs **ARP-based network discovery** and **TCP SYN port scanning** to identify active devices and open ports.

## Features
- **ARP Scan**: Detects active devices on a subnet using ARP requests.
- **TCP Scan**: Performs a SYN scan on specified ports to check for open services.
- **CIDR Support**: Scans entire subnets (e.g., `192.168.1.1/24`).
- **Custom Port Ranges**: Supports scanning individual ports or a range.

## Installation
### Prerequisites
- Python 3.x  
- Scapy  
- Run the following command to install dependencies:

```sh
pip install scapy
```

## Usage
Run the script using the command-line interface.

### ARP Scan (Network Discovery)
```sh
python scanner.py ARP <target-ip>
```
Examples:
```sh
python scanner.py ARP 192.168.1.1
python scanner.py ARP 192.168.1.1/24
```

### TCP Port Scan
```sh
python scanner.py TCP <target-ip> <port(s)>
```
Examples:
```sh
python scanner.py TCP 192.168.1.1 80 443
python scanner.py TCP 192.168.1.1 20 21 22 25 53
python scanner.py TCP 192.168.1.1 20 80 --range
```
Use `--range` to specify a port range (e.g., `20 80` scans ports from 20 to 80).

## Example Output
### ARP Scan
```
192.168.1.1 ==> 00:1A:2B:3C:4D:5E
192.168.1.2 ==> A1:B2:C3:D4:E5:F6
```

### TCP Scan
```
Port 80 is open.
Port 443 is open.
```

## Notes
- **Requires root privileges** (run with `sudo` on Linux/macOS).
- Works on local networks for ARP scanning.
- Ensure you have permission before scanning any network.

## License
MIT License

## Author
[Vikas Nayak](https://github.com/vikas-nayak)

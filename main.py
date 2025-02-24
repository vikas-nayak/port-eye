import argparse
from scapy.all import ARP, srp, sr, TCP, IP
import socket
from scapy.layers.l2 import Ether


def arp_scan(ip):
    """Scans a network using ARP requests."""
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(request, timeout=2, retry=1)
    return [{'IP': received.psrc, 'MAC': received.hwsrc} for _, received in ans]


def tcp_scan(ip, ports):
    """Scans specified TCP ports using SYN packets."""
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError(f'Hostname {ip} could not be resolved.')

    ans, _ = sr(syn, timeout=2, retry=1)
    return [received[TCP].sport for _, received in ans if received[TCP].flags == "SA"]


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    arp_parser = subparsers.add_parser('ARP', help='Perform an ARP network scan.')
    arp_parser.add_argument('IP', help='Target IP or subnet (e.g., 192.168.1.1/24).')

    tcp_parser = subparsers.add_parser('TCP', help='Perform a TCP SYN scan.')
    tcp_parser.add_argument('IP', help='Target IP or hostname.')
    tcp_parser.add_argument('ports', nargs='+', type=int, help='Ports to scan.')
    tcp_parser.add_argument('--range', action='store_true', help='Scan a range of ports.')

    args = parser.parse_args()

    if args.command == 'ARP':
        for mapping in arp_scan(args.IP):
            print(f"{mapping['IP']} ==> {mapping['MAC']}")

    elif args.command == 'TCP':
        ports = tuple(args.ports) if args.range else args.ports
        try:
            for port in tcp_scan(args.IP, ports):
                print(f'Port {port} is open.')
        except ValueError as error:
            print(error)
            exit(1)


if __name__ == '__main__':
    main()

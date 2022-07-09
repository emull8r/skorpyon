#!/usr/bin/python3
"""Skorpyon: The main class of the Skorpyon program."""
import sys
from ip_scanner import Scanner

if __name__ == '__main__':

    if len(sys.argv) < 4:
        print('Usage: ./skorpyon.py <subnet> <start port> <end port>')
        print('Example: ./skorpyon.py 192.168.0.1/24 1 65535\n')

    elif len(sys.argv) == 4:
        subnet = sys.argv[1]
        startPort = int(sys.argv[2])
        endPort = int(sys.argv[3])
        scanner = Scanner()
        hosts = scanner.get_hosts(subnet)
        for address in hosts:
            scanner.scan_host(address, startPort, endPort)
